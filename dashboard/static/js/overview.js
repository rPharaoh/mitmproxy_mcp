/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – overview.js
   Overview / Dashboard page.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

async function loadOverview() {
    try {
        const [stats, summary, domains, requests] = await Promise.all([
            api('/api/stats'),
            api('/api/summary?hours=' + (document.getElementById('summary-hours')?.value || 24)),
            api('/api/domains?limit=10'),
            api('/api/requests?limit=10'),
        ]);

        // Stat cards
        document.getElementById('stats-grid').innerHTML = [
            statCard('Total Requests', stats.total_requests || 0),
            statCard('Unique Hosts', stats.unique_hosts || 0),
            statCard('Avg Latency', formatDuration(stats.avg_duration_ms)),
            statCard('Total Data', formatBytes(stats.total_bytes || 0)),
            statCard('Errors', stats.errors || 0, stats.errors > 0 ? 'negative' : ''),
            statCard('Success', stats.success || 0, 'positive'),
        ].join('');

        // Timeline chart
        if (summary.hourly_breakdown && summary.hourly_breakdown.length > 0) {
            makeChart('chart-timeline', {
                type: 'bar',
                data: {
                    labels: summary.hourly_breakdown.map(h => h.hour?.substring(11, 16) || ''),
                    datasets: [{
                        label: 'Requests',
                        data: summary.hourly_breakdown.map(h => h.requests || 0),
                        backgroundColor: 'rgba(88,166,255,0.4)',
                        borderColor: '#58a6ff',
                        borderWidth: 1,
                        borderRadius: 3,
                    }]
                },
                options: { scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } }
            });
        }

        // Hosts chart
        if (domains.length > 0) {
            makeChart('chart-hosts', {
                type: 'doughnut',
                data: {
                    labels: domains.map(d => d.host),
                    datasets: [{
                        data: domains.map(d => d.total_requests),
                        backgroundColor: chartColors,
                        borderWidth: 0,
                    }]
                },
                options: {
                    cutout: '60%',
                    plugins: { legend: { position: 'right', labels: { boxWidth: 12, padding: 8 } } },
                }
            });
        }

        // Recent table
        const recentReqs = requests.requests || requests;
        document.getElementById('overview-recent-table').innerHTML = requestsTable(recentReqs);

    } catch (e) {
        console.error('Overview load error:', e);
    }
}

document.getElementById('summary-hours')?.addEventListener('change', loadOverview);
