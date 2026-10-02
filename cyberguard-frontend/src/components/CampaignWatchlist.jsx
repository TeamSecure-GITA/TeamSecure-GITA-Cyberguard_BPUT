import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

const apiBaseUrl = getApiBaseUrl();

export default function CampaignWatchlist({ accessToken }) {
  const [campaign, setCampaign] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.post(
      `${apiBaseUrl}/api/v1/prevention/campaign-watch`,
      {},
      { headers: { Authorization: `Bearer ${accessToken}` } },
    ).then((response) => setCampaign(response.data)).catch(() => setCampaign(null));
  }, [accessToken]);

  if (!campaign) {
    return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">No campaign watch activity.</section>;
  }

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Campaign prevention</p>
      <h2 className="text-xl font-bold text-white mt-1">Campaign Watchlist</h2>
      <div className="mt-4 rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3 text-xs text-cyan-100">
        <div className="font-bold uppercase">{campaign.campaign_id}</div>
        <div className="mt-2">Status: {campaign.watch_status}</div>
        <div className="mt-2">Stored incidents analyzed: {campaign.source_incident_count}</div>
      </div>
      <div className="mt-4 space-y-2 text-xs text-slate-300">
        <div>Users affected: {campaign.affected_users.join(', ') || 'none'}</div>
        <div>Blocked domains: {campaign.global_block_actions.join(', ') || 'none'}</div>
        <div>Signals: {campaign.matched_signals.join(' | ') || 'none'}</div>
      </div>
    </section>
  );
}
