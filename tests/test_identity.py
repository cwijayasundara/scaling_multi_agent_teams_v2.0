import json
import pickle
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from teamlab.analytics import digest
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.identity import key_id_for, new_credential, verify_journal_signatures
from teamlab.security import CredentialExpired, RunStopped, SecurityError


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


class Clock:
    def __init__(self, base):
        self.base, self.offset = base, 0.0

    def advance(self, seconds):
        self.offset += seconds
        assert self.offset < 1200, "stay inside the run deadline"

    def __call__(self):
        return self.base + self.offset


@pytest.fixture
def clock(monkeypatch):
    # Patch time.time globally so store, controller leases and gateway agree.
    fake = Clock(time.time())
    monkeypatch.setattr(time, 'time', fake)
    return fake


def test_each_agent_has_distinct_registered_key(controller):
    creds = [controller.lead, controller.verifier, *controller.worker_tokens.values()]
    assert len({c.key_id for c in creds}) == len(creds) == 6
    with controller.store.connect() as db:
        rows = db.execute('SELECT key_id FROM agent_keys WHERE run_id=?', (controller.run_id,)).fetchall()
    assert {r['key_id'] for r in rows} == {c.key_id for c in creds}


def test_audit_records_are_signed_and_verify(controller):
    controller.run_scripted()
    n = verify_journal_signatures(controller.store.root / 'audit.jsonl', controller.store)
    assert n == controller.gateway.journal.verify() > 20


def _rewrite(controller, mutate):
    controller.run_scripted()
    path = controller.store.root / 'audit.jsonl'
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    mutate(lines[2]['record'])
    previous = '0' * 64
    for item in lines:
        item['previous'] = previous
        item.pop('hash', None)
        item['hash'] = digest(item)
        previous = item['hash']
    path.write_text(''.join(json.dumps(item, sort_keys=True, separators=(',', ':')) + '\n' for item in lines))
    assert controller.gateway.journal.verify() == len(lines)  # chain still valid
    return path


def test_tampered_signed_envelope_fails_cryptographic_check(controller):
    # Only request.issued_at changes: every consistency check passes, so the
    # Ed25519 verification itself is what must reject the record.
    path = _rewrite(controller, lambda r: r['request'].__setitem__('issued_at', r['request']['issued_at'] + 1))
    with pytest.raises(SecurityError, match='bad signature'):
        verify_journal_signatures(path, controller.store)


def test_signature_check_is_what_rejects_tampering(controller, monkeypatch):
    path = _rewrite(controller, lambda r: r['request'].__setitem__('issued_at', r['request']['issued_at'] + 1))
    monkeypatch.setattr('teamlab.identity.verify_signature', lambda *a: True)
    assert verify_journal_signatures(path, controller.store) > 20


def test_record_differing_from_signed_request_is_detected(controller):
    path = _rewrite(controller, lambda r: r.__setitem__('action', 'publish'))
    with pytest.raises(SecurityError, match='differs from signed request'):
        verify_journal_signatures(path, controller.store)


def test_request_attributed_to_another_agent_is_detected(controller):
    path = _rewrite(controller, lambda r: r['request'].__setitem__('agent_id', 'worker-9'))
    with pytest.raises(SecurityError, match='not registered to this agent'):
        verify_journal_signatures(path, controller.store)


def test_unsigned_audit_record_is_rejected(controller):
    controller.gateway.journal.append({'operation_id': 'x', 'action': 'post_note'})
    with pytest.raises(SecurityError, match='unsigned audit record'):
        verify_journal_signatures(controller.store.root / 'audit.jsonl', controller.store)


def test_plain_token_string_is_not_a_credential(controller):
    with pytest.raises(SecurityError, match='invalid service identity'):
        controller.claim(controller.worker_tokens[0].token)


def test_bad_request_signature_stops_team(controller, monkeypatch):
    cred = controller.worker_tokens[0]
    monkeypatch.setattr(cred, 'sign', lambda envelope: 'AAAA')
    with pytest.raises(SecurityError):
        controller.claim(cred)
    assert controller.store.run(controller.run_id)['state'] == 'STOPPED'


def test_credential_cannot_be_pickled_or_leak_in_repr(controller):
    cred = controller.lead
    with pytest.raises(TypeError):
        pickle.dumps(cred)
    assert cred.token not in repr(cred) and 'PRIVATE' not in repr(cred)


def test_bundle_exports_public_keys(controller):
    out = controller.run_scripted()
    agents = json.loads((out / 'agents.json').read_text())
    assert {a['agent_id'] for a in agents} == {'coordinator', 'verifier', 'worker-0', 'worker-1', 'worker-2', 'worker-3'}
    assert all(key_id_for(a['public_key']) == a['key_id'] for a in agents)


def test_idle_agent_past_ttl_refreshes_and_rotates_token(controller, clock):
    cred = controller.worker_tokens[0]; old = cred.token
    clock.advance(301)
    assert controller.claim(cred)['state'] == 'LEASED'
    assert cred.token != old
    assert cred.expires_at > time.time()
    refreshed = [e for e in controller.store.events(controller.run_id) if e['kind'] == 'credential.refreshed']
    assert [e['detail']['agent_id'] for e in refreshed] == ['worker-0']
    assert refreshed[0]['detail']['key_id'] == cred.key_id


def test_copied_bearer_token_without_key_expires(controller, clock):
    cred = controller.worker_tokens[0]
    thief = new_credential(cred.agent_id, cred.token, cred.expires_at)  # different key, same bearer string
    clock.advance(301)
    with pytest.raises(SecurityError):
        controller.claim(thief)
    assert controller.store.run(controller.run_id)['state'] in ('RUNNING', 'STOPPED')
    events = controller.store.events(controller.run_id)
    assert not any(e['kind'] == 'action.authorized' and e['agent_id'] == 'worker-0' for e in events)
    task = next(t for t in controller.store.tasks(controller.run_id) if t['shard'] == 0)
    assert task['state'] != 'LEASED' and task['owner'] is None
    assert not any(e['kind'] == 'credential.refreshed' for e in events)


def test_expired_copied_bearer_token_is_rejected_without_stopping_team(controller, clock):
    cred = controller.worker_tokens[0]
    thief = new_credential(cred.agent_id, cred.token, cred.expires_at)
    clock.advance(301)
    with pytest.raises(CredentialExpired):
        controller.claim(thief)
    assert controller.store.run(controller.run_id)['state'] == 'RUNNING'
    rejected = [e['detail'] for e in controller.store.events(controller.run_id) if e['kind'] == 'credential.rejected']
    assert rejected and rejected[0]['agent_id'] == 'worker-0' and rejected[0]['key_id'] == thief.key_id


def test_old_token_is_invalid_after_rotation(controller, clock):
    cred = controller.worker_tokens[0]; old = cred.token
    clock.advance(250); controller.claim(cred)
    assert old not in controller.gateway._sessions
    assert cred.token in controller.gateway._sessions


def test_refresh_fails_after_operator_stop(controller, clock):
    cred = controller.worker_tokens[0]
    controller.store.stop(controller.run_id, 'operator')
    clock.advance(301)
    with pytest.raises(RunStopped):
        controller.gateway.refresh(cred)


def test_concurrent_calls_at_refresh_boundary_all_succeed(controller, clock):
    cred = controller.lead
    clock.advance(250)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: controller.progress(cred), range(8)))
    assert len(results) == 8
    assert sum(e['kind'] == 'credential.refreshed' for e in controller.store.events(controller.run_id)) == 1


def test_credential_ttl_is_configurable(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=20, seed=3)
    c = Controller(tmp_path / "run", source, workers=1, credential_ttl=120)
    assert 60 < c.lead.expires_at - time.time() <= 120


def test_lookup_racing_a_rotation_still_resolves(controller):
    # The caller reads the old token, then another thread rotates it before
    # the session lookup runs. The legitimate call must still succeed.
    gateway, cred = controller.gateway, controller.lead
    old, fired = cred.token, []

    class RacingSessions(dict):
        def get(self, key, default=None):
            if key == old and not fired:
                fired.append(True)
                gateway.refresh(cred)  # rotates and retires the old token now
            return super().get(key, default)

    gateway._sessions = RacingSessions(gateway._sessions)
    assert controller.progress(cred)['tasks']
    assert fired and cred.token != old and old not in gateway._sessions


def test_concurrent_direct_refreshes_are_serialized(controller):
    cred = controller.lead
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda _: controller.gateway.refresh(cred), range(4)))
    assert sum(e['kind'] == 'credential.refreshed' for e in controller.store.events(controller.run_id)) == 4
    assert controller.gateway.identity(cred).agent_id == 'coordinator'
    assert sum(s.identity.agent_id == 'coordinator' for s in controller.gateway._sessions.values()) == 1
