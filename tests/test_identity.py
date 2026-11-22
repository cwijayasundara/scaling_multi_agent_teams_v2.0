import json
import pickle

import pytest

from teamlab.analytics import digest
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.identity import key_id_for, verify_journal_signatures
from teamlab.security import SecurityError


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


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


def test_forged_audit_signature_is_detected(controller):
    controller.run_scripted()
    path = controller.store.root / 'audit.jsonl'
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    lines[2]['record']['request']['agent_id'] = 'worker-9'
    previous = '0' * 64
    for item in lines:
        item['previous'] = previous
        item.pop('hash', None)
        item['hash'] = digest(item)
        previous = item['hash']
    path.write_text(''.join(json.dumps(item, sort_keys=True, separators=(',', ':')) + '\n' for item in lines))
    assert controller.gateway.journal.verify() == len(lines)
    with pytest.raises(SecurityError, match='signature'):
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
