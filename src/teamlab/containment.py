"""Graduated per-agent containment: strikes move one agent ACTIVE -> RESTRICTED -> QUARANTINED.

Gateway code, not a monitor. States only move down; nothing moves an agent back
up. A quarantined agent loses its sessions and its leases. Only when its work
cannot be reassigned (coordinator, verifier, or a fixed-workflow worker) is the
run paused; deterministic blocks still stop the whole team elsewhere.
"""
from .store import AGENT_STATES, Store

# Roles whose quarantine leaves work nobody else can take over.
_UNREASSIGNABLE_ROLES = ("coordinator", "verifier")


def _rank(state: str) -> int:
    return AGENT_STATES.index(state)


def _collaborative(db, run_id: str) -> bool:
    """Whether the run's work is on the shared board, from its recorded workflow."""
    workflow = Store.run_attribute(db, run_id, "workflow")
    if workflow is not None:
        return workflow != "fixed"
    # Legacy runs recorded before run_attributes: infer from the board.
    if db.execute("SELECT 1 FROM events WHERE run_id=? AND kind=?", (run_id, "execution.configured")).fetchone():
        return True
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work'").fetchone():
        return False
    return db.execute("SELECT 1 FROM work WHERE run_id=?", (run_id,)).fetchone() is not None


def _release_leases(db, run_id: str, agent_id: str) -> None:
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work'").fetchone():
        db.execute("UPDATE work SET state='READY',owner=NULL,fence=fence+1,version=version+1 "
                   "WHERE run_id=? AND owner=? AND state='LEASED'", (run_id, agent_id))
    db.execute("UPDATE tasks SET state='READY',owner=NULL,fence=fence+1 WHERE run_id=? AND owner=? AND state='LEASED'",
               (run_id, agent_id))


def strike(store, gateway, run_id: str, agent_id: str, source: str, detail: dict) -> str:
    """Add the policy's strikes for source to agent_id and return its (possibly new) state."""
    policy = gateway.access.containment
    pause = False
    with store.transaction() as db:
        store.lock_run(db, run_id)  # serializes the first insert of the agent's state row
        current = store.agent_state(db, run_id, agent_id)
        strikes = current["strikes"] + policy["strikes"][source]
        earned = ("QUARANTINED" if strikes >= policy["quarantine_at_strikes"]
                  else "RESTRICTED" if strikes >= policy["restrict_at_strikes"] else "ACTIVE")
        state = max(current["state"], earned, key=_rank)  # never moves up
        store.set_agent_state(db, run_id, agent_id, state, strikes, source)
        store.event(db, run_id, "controller", "agent.strike",
                    {"agent_id": agent_id, "source": source, "strikes": strikes, "detail": detail})
        if state != current["state"]:
            store.event(db, run_id, "controller", "agent." + state.lower(),
                        {"agent_id": agent_id, "strikes": strikes, "source": source})
        if state == "QUARANTINED" and current["state"] != "QUARANTINED":
            gateway.revoke_agent(agent_id)
            _release_leases(db, run_id, agent_id)
            role = db.execute("SELECT role FROM agent_keys WHERE run_id=? AND agent_id=?", (run_id, agent_id)).fetchone()
            pause = role is None or role["role"] in _UNREASSIGNABLE_ROLES or not _collaborative(db, run_id)
    if pause:
        store.stop(run_id, f"agent quarantined: {agent_id}", "PAUSED")
    return state


def quarantined(store, run_id: str) -> set[str]:
    with store.connect() as db:
        return {r["agent_id"] for r in db.execute(
            "SELECT agent_id FROM agent_states WHERE run_id=? AND state=?", (run_id, "QUARANTINED"))}


def agent_states(store, run_id: str) -> dict:
    """Every registered agent's containment state, read-only; no state row means ACTIVE."""
    with store.connect() as db:
        agents = [r["agent_id"] for r in db.execute(
            "SELECT DISTINCT agent_id FROM agent_keys WHERE run_id=? ORDER BY agent_id", (run_id,))]
        return {agent: store.agent_state(db, run_id, agent) for agent in agents}
