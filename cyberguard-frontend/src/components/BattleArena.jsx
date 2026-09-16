import React from 'react';

export default function BattleArena({ battle, onRun, busy = false }) {
  return <section className="glass-panel p-5" aria-label="AI defender versus attacker battle arena">
    <div className="panel-heading"><div><div className="eyebrow">AI defender vs attacker</div><h3>Battle arena</h3></div><button type="button" className="icon-action" onClick={onRun} disabled={busy} title="Run battle simulation">{busy ? '...' : 'Run'}</button></div>
    <div className="battle-result mt-4">{battle ? <><strong>{battle.winner === 'defender' ? 'DEFENDER ADVANTAGE' : 'ATTACKER PRESSURE'}</strong><span>Surviving risk {battle.surviving_risk}% · {(battle.rounds || []).length} rounds modeled</span></> : <span>Choose controls, then run the live scenario.</span>}</div>
  </section>;
}
