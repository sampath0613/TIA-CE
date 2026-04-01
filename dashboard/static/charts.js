const dashboardConfig = window.THREAT_INTEL_DASHBOARD || {};

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function verdictBadgeClass(verdict) {
  if (verdict === 'malicious') return 'verdict-badge verdict-malicious';
  if (verdict === 'suspicious') return 'verdict-badge verdict-suspicious';
  return 'verdict-badge verdict-clean';
}

async function apiFetch(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (dashboardConfig.apiKey) {
    headers['X-API-Key'] = dashboardConfig.apiKey;
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API request failed: ${response.status} ${text}`);
  }

  return response.json();
}

function toSourceDatasets(volumeRows) {
  const dates = [...new Set(volumeRows.map((row) => row.date))].sort();
  const bySource = {};

  for (const row of volumeRows) {
    const sourceId = row.source_id;
    bySource[sourceId] = bySource[sourceId] || {};
    bySource[sourceId][row.date] = row.ioc_count;
  }

  const palette = ['#4dd5c6', '#60a5fa', '#f59e0b', '#f43f5e', '#a78bfa', '#34d399'];
  const sourceIds = Object.keys(bySource).sort();

  const datasets = sourceIds.map((sourceId, index) => ({
    label: sourceId,
    data: dates.map((date) => bySource[sourceId][date] || 0),
    borderColor: palette[index % palette.length],
    backgroundColor: `${palette[index % palette.length]}33`,
    borderWidth: 2,
    tension: 0.25,
    fill: false,
  }));

  return { dates, datasets };
}

let volumeChart = null;
let confidenceChart = null;

function renderVolumeChart(volumeRows) {
  const canvas = document.getElementById('volumeChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const { dates, datasets } = toSourceDatasets(volumeRows);

  if (volumeChart) volumeChart.destroy();
  volumeChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: dates,
      datasets,
    },
    options: {
      plugins: {
        legend: { labels: { color: '#cbd5e1' } },
      },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
      },
    },
  });
}

function renderConfidenceChart(distributionRows) {
  const canvas = document.getElementById('confidenceChart');
  if (!canvas || typeof Chart === 'undefined') return;

  if (confidenceChart) confidenceChart.destroy();
  confidenceChart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: distributionRows.map((row) => row.bucket),
      datasets: [
        {
          label: 'IOC Count',
          data: distributionRows.map((row) => row.count),
          backgroundColor: '#60a5fa88',
          borderColor: '#60a5fa',
          borderWidth: 1,
        },
      ],
    },
    options: {
      plugins: {
        legend: { labels: { color: '#cbd5e1' } },
      },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
      },
    },
  });
}

function renderFeedQualityTable(feedHealthRows) {
  const body = document.getElementById('feedQualityBody');
  if (!body) return;

  body.innerHTML = feedHealthRows
    .map((row) => {
      const lastIngested = row.last_ingestion_at ? new Date(row.last_ingestion_at).toLocaleString() : 'Never';
      return `
        <tr>
          <td>${escapeHtml(row.display_name || row.source_id)}</td>
          <td>${Number(row.source_weight).toFixed(2)}</td>
          <td>${Number(row.avg_confidence).toFixed(3)}</td>
          <td>${(Number(row.cumulative_fp_rate) * 100).toFixed(2)}%</td>
          <td>${escapeHtml(lastIngested)}</td>
          <td>${Number(row.ioc_count)}</td>
        </tr>
      `;
    })
    .join('');
}

function renderTopIocTable(iocRows) {
  const body = document.getElementById('topIocBody');
  if (!body) return;

  body.innerHTML = iocRows
    .map((row) => {
      const verdict = row.verdict || 'clean';
      const encodedValue = encodeURIComponent(row.ioc_value);
      return `
        <tr>
          <td><a class="ioc-link" href="/dashboard/ioc/${encodedValue}">${escapeHtml(row.ioc_value)}</a></td>
          <td>${escapeHtml(row.ioc_type)}</td>
          <td>${Number(row.confidence_score).toFixed(3)}</td>
          <td><span class="${verdictBadgeClass(verdict)}">${escapeHtml(verdict)}</span></td>
          <td>${(row.sources || []).map(escapeHtml).join(', ')}</td>
        </tr>
      `;
    })
    .join('');
}

async function refreshOverview() {
  const [volumeRows, distributionRows, feedHealthRows, topRows] = await Promise.all([
    apiFetch('/stats/ioc-volume?days=7'),
    apiFetch('/stats/confidence-distribution'),
    apiFetch('/stats/feed-health'),
    apiFetch('/ioc/top?limit=20&verdict=malicious'),
  ]);

  renderVolumeChart(volumeRows);
  renderConfidenceChart(distributionRows);
  renderFeedQualityTable(feedHealthRows);
  renderTopIocTable(topRows);
}

function renderIocHeader(ioc) {
  const heading = document.getElementById('iocValueHeading');
  const meta = document.getElementById('iocMetaLine');
  const score = document.getElementById('iocScoreValue');
  const badge = document.getElementById('iocVerdictBadge');

  if (!heading || !meta || !score || !badge) return;

  heading.textContent = `IOC: ${ioc.ioc_value}`;
  meta.textContent = `Type: ${ioc.ioc_type} | Sources: ${(ioc.sources || []).length} | First seen: ${new Date(ioc.first_seen).toLocaleString()}`;
  score.textContent = Number(ioc.confidence_score).toFixed(3);
  badge.className = verdictBadgeClass(ioc.verdict);
  badge.textContent = ioc.verdict;
}

function renderBreakdown(breakdown) {
  const timelineBody = document.getElementById('timelineBody');
  const breakdownBody = document.getElementById('breakdownBody');
  const summary = document.getElementById('breakdownSummary');
  if (!timelineBody || !breakdownBody || !summary) return;

  const rows = breakdown.rows || [];

  timelineBody.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml(row.display_name || row.source_id)}</td>
        <td>${new Date(row.last_seen_by_source).toLocaleString()}</td>
        <td>${row.confidence_raw === null ? 'n/a' : Number(row.confidence_raw).toFixed(3)}</td>
        <td>${(row.raw_tags || []).map(escapeHtml).join(', ')}</td>
      </tr>
    `
    )
    .join('');

  breakdownBody.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml(row.display_name || row.source_id)}</td>
        <td>${Number(row.weight).toFixed(3)}</td>
        <td>${Number(row.lambda).toFixed(4)}</td>
        <td>${Number(row.decay).toFixed(4)}</td>
        <td>${Number(row.contribution).toFixed(4)}</td>
      </tr>
    `
    )
    .join('');

  summary.textContent = `Base Sum: ${Number(breakdown.base_weighted_sum).toFixed(4)} | Corroboration Multiplier: ${Number(
    breakdown.corroboration_multiplier
  ).toFixed(4)} | Recomputed Score: ${Number(breakdown.recomputed_score).toFixed(4)}`;
}

async function refreshIocDetail(iocValue) {
  const encoded = encodeURIComponent(iocValue);
  const [ioc, breakdown] = await Promise.all([
    apiFetch(`/ioc/${encoded}`),
    apiFetch(`/ioc/breakdown/${encoded}`),
  ]);

  renderIocHeader(ioc);
  renderBreakdown(breakdown);
}

function setupFeedbackButtons(iocValue) {
  const buttons = document.querySelectorAll('[data-verdict]');
  const status = document.getElementById('feedbackStatus');
  const encoded = encodeURIComponent(iocValue);

  for (const button of buttons) {
    button.addEventListener('click', async () => {
      const verdict = button.getAttribute('data-verdict');
      if (!verdict) return;

      try {
        if (status) status.textContent = 'Submitting analyst feedback...';
        await apiFetch(`/ioc/${encoded}/verdict`, {
          method: 'POST',
          body: JSON.stringify({ verdict, notes: 'Submitted from dashboard' }),
        });
        if (status) status.textContent = 'Feedback accepted and score updated.';
        await refreshIocDetail(iocValue);
      } catch (error) {
        if (status) status.textContent = `Feedback failed: ${String(error)}`;
      }
    });
  }
}

async function initOverviewPage() {
  await refreshOverview();
  const refreshMs = Number(dashboardConfig.refreshSeconds || 60) * 1000;
  window.setInterval(() => {
    refreshOverview().catch((error) => console.error('Overview refresh failed', error));
  }, refreshMs);
}

async function initIocDetailPage(container) {
  const iocValue = container.getAttribute('data-ioc-value') || '';
  if (!iocValue) return;

  await refreshIocDetail(iocValue);
  setupFeedbackButtons(iocValue);
}

document.addEventListener('DOMContentLoaded', () => {
  const page = document.querySelector('[data-page]');
  if (!page) return;

  const pageName = page.getAttribute('data-page');

  if (pageName === 'overview') {
    initOverviewPage().catch((error) => console.error('Dashboard init failed', error));
    return;
  }

  if (pageName === 'ioc-detail') {
    initIocDetailPage(page).catch((error) => console.error('IOC detail init failed', error));
  }
});
