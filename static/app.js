/* Dashboard frontend — polls /api/state every second and updates charts. */

const POLL_MS = 1000;

const fmt = {
  bytes(n) {
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(n >= 100 ? 0 : 1)} ${u[i]}`;
  },
  uptime(s) {
    s = Math.floor(s);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60),
          sec = s % 60;
    if (h) return `${h}h ${m}m ${sec}s`;
    if (m) return `${m}m ${sec}s`;
    return `${sec}s`;
  },
  time(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString();
  },
  num(n) { return Number(n || 0).toLocaleString(); },
};

const seenAlerts = new Set();

// ----- Charts -----
const baseChartOpts = (yLabel) => ({
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  interaction: { mode: "index", intersect: false },
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: "#0b1020",
      borderColor: "#243056",
      borderWidth: 1,
    },
  },
  scales: {
    x: {
      grid: { color: "rgba(31,39,74,0.5)" },
      ticks: { color: "#8a93b6", maxTicksLimit: 8 },
    },
    y: {
      grid: { color: "rgba(31,39,74,0.5)" },
      ticks: { color: "#8a93b6" },
      title: { display: true, text: yLabel, color: "#8a93b6" },
    },
  },
});

const ctxPackets = document.getElementById("chartPackets").getContext("2d");
const chartPackets = new Chart(ctxPackets, {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "+3σ",
        data: [],
        borderColor: "transparent",
        backgroundColor: "rgba(124,92,255,0.10)",
        fill: "+1",
        pointRadius: 0,
        order: 5,
      },
      {
        label: "-3σ",
        data: [],
        borderColor: "transparent",
        backgroundColor: "rgba(124,92,255,0.10)",
        fill: false,
        pointRadius: 0,
        order: 6,
      },
      {
        label: "baseline μ",
        data: [],
        borderColor: "#b388ff",
        borderDash: [5, 4],
        borderWidth: 1.5,
        pointRadius: 0,
        fill: false,
        order: 4,
      },
      {
        label: "packets/s",
        data: [],
        borderColor: "#5cc8ff",
        backgroundColor: "rgba(92,200,255,0.10)",
        borderWidth: 2,
        pointRadius: (ctx) => ctx.raw && ctx.raw.anom ? 4 : 0,
        pointBackgroundColor: "#ff5c7a",
        pointBorderColor: "#ff5c7a",
        fill: true,
        tension: 0.25,
        parsing: { yAxisKey: "y" },
        order: 1,
      },
    ],
  },
  options: baseChartOpts("packets / sec"),
});

const ctxBytes = document.getElementById("chartBytes").getContext("2d");
const chartBytes = new Chart(ctxBytes, {
  type: "line",
  data: {
    labels: [],
    datasets: [{
      label: "bytes/s",
      data: [],
      borderColor: "#1ed8a3",
      backgroundColor: "rgba(30,216,163,0.10)",
      borderWidth: 2,
      pointRadius: 0,
      fill: true,
      tension: 0.25,
    }],
  },
  options: {
    ...baseChartOpts("bytes / sec"),
    scales: {
      ...baseChartOpts("bytes / sec").scales,
      y: {
        ...baseChartOpts("bytes / sec").scales.y,
        ticks: {
          color: "#8a93b6",
          callback: (v) => fmt.bytes(v),
        },
      },
    },
  },
});

const ctxProto = document.getElementById("chartProto").getContext("2d");
const chartProto = new Chart(ctxProto, {
  type: "doughnut",
  data: {
    labels: ["TCP", "UDP", "ICMP"],
    datasets: [{
      data: [0, 0, 0],
      backgroundColor: ["#5cc8ff", "#7c5cff", "#ff5c7a"],
      borderColor: "#131a32",
      borderWidth: 2,
    }],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: { position: "bottom", labels: { color: "#8a93b6", font: { size: 11 } } },
    },
  },
});

const ctxPorts = document.getElementById("chartPorts").getContext("2d");
const chartPorts = new Chart(ctxPorts, {
  type: "bar",
  data: {
    labels: [], datasets: [{
      label: "bytes",
      data: [],
      backgroundColor: "rgba(92,200,255,0.6)",
      borderColor: "#5cc8ff",
      borderWidth: 1,
    }],
  },
  options: {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { color: "rgba(31,39,74,0.5)" },
        ticks: { color: "#8a93b6", callback: (v) => fmt.bytes(v) },
      },
      y: { grid: { display: false }, ticks: { color: "#8a93b6" } },
    },
  },
});

// ----- Helpers -----
function setText(id, txt) { document.getElementById(id).textContent = txt; }

function renderTalkers(rows) {
  const tbody = document.querySelector("#tbl-talkers tbody");
  tbody.innerHTML = "";
  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="2" class="muted">No traffic yet.</td></tr>`;
    return;
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${r.ip}</td><td class="num">${fmt.bytes(r.bytes)}</td>`;
    tbody.appendChild(tr);
  }
}

function renderBaseline(snap) {
  const tbody = document.querySelector("#tbl-baseline tbody");
  tbody.innerHTML = "";
  const order = ["packets", "bytes", "tcp_packets", "udp_packets",
    "unique_src_ips", "unique_dst_ips", "unique_dst_ports"];
  for (const m of order) {
    const s = snap[m] || { mean: 0, stdev: 0, n: 0 };
    const isBytes = m === "bytes";
    const meanStr = isBytes ? fmt.bytes(s.mean) : fmt.num(s.mean.toFixed(1));
    const stdStr  = isBytes ? fmt.bytes(s.stdev) : fmt.num(s.stdev.toFixed(1));
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${m}</td>` +
      `<td class="num">${meanStr}</td>` +
      `<td class="num">${stdStr}</td>` +
      `<td class="num">${s.n}</td>`;
    tbody.appendChild(tr);
  }
}

function renderAlerts(alerts) {
  const feed = document.getElementById("alerts-feed");
  document.getElementById("alerts-count").textContent =
    `${alerts.length} alert${alerts.length === 1 ? "" : "s"}`;

  if (alerts.length === 0) {
    feed.innerHTML = `<div class="empty">No alerts yet — system is learning the baseline.</div>`;
    return;
  }
  feed.innerHTML = "";
  for (const a of alerts) {
    const fresh = !seenAlerts.has(a.id);
    seenAlerts.add(a.id);
    const row = document.createElement("div");
    row.className = `alert-row sev-${a.severity}` + (fresh ? " fresh" : "");
    row.innerHTML =
      `<div class="time">${fmt.time(a.ts)}</div>` +
      `<div>` +
        `<div class="title">${escapeHtml(a.title)}</div>` +
        `<div class="desc">${escapeHtml(a.description)}</div>` +
      `</div>` +
      `<div class="type-tag">${a.type}</div>`;
    feed.appendChild(row);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ----- Main poll -----
async function tick() {
  try {
    const [stateR, alertsR] = await Promise.all([
      fetch("/api/state").then(r => r.json()),
      fetch("/api/alerts?limit=100").then(r => r.json()),
    ]);
    update(stateR, alertsR.alerts || []);
  } catch (e) {
    console.error("poll failed", e);
  }
}

function update(state, alerts) {
  // Status pill
  const pill = document.getElementById("status-pill");
  if (state.status === "monitoring") {
    pill.textContent = "monitoring";
    pill.className = "pill pill-mon";
  } else {
    pill.textContent = `training ${(state.warmup_progress * 100 | 0)}%`;
    pill.className = "pill pill-train";
  }

  setText("uptime", fmt.uptime(state.uptime_seconds || 0));

  // KPIs
  setText("kpi-pps", fmt.num(state.current_pps));
  setText("kpi-bps", fmt.bytes(state.current_bps));
  setText("kpi-flows", fmt.num(state.total_flows));

  const lastWin = state.recent_windows && state.recent_windows.length
    ? state.recent_windows[state.recent_windows.length - 1] : null;
  if (lastWin) {
    setText("kpi-ips", `${lastWin.unique_src_ips} / ${lastWin.unique_dst_ips}`);
  }

  const bp = state.baseline_overlay && state.baseline_overlay.packets;
  if (bp) {
    setText("kpi-pps-sub",
      `baseline μ=${bp.mean.toFixed(1)} σ=${bp.stdev.toFixed(1)}`);
  }
  const bb = state.baseline_overlay && state.baseline_overlay.bytes;
  if (bb) {
    setText("kpi-bps-sub",
      `baseline μ=${fmt.bytes(bb.mean)} σ=${fmt.bytes(bb.stdev)}`);
  }

  const sevs = state.alert_summary || {};
  setText("kpi-crit", sevs.critical || 0);
  setText("kpi-warn", sevs.warning || 0);
  setText("kpi-info", sevs.info || 0);

  // ----- charts -----
  const labels = state.recent_windows.map(w => fmt.time(w.end_ts));
  const pps = state.recent_windows.map(w => ({ x: fmt.time(w.end_ts), y: w.packets, anom: w.anomalous }));
  const bps = state.recent_windows.map(w => w.bytes);

  const meanP = bp ? bp.mean : 0;
  const stdP  = bp ? bp.stdev : 0;
  const upper = labels.map(() => meanP + 3 * stdP);
  const lower = labels.map(() => Math.max(0, meanP - 3 * stdP));
  const meanLine = labels.map(() => meanP);

  chartPackets.data.labels = labels;
  chartPackets.data.datasets[0].data = upper;
  chartPackets.data.datasets[1].data = lower;
  chartPackets.data.datasets[2].data = meanLine;
  chartPackets.data.datasets[3].data = pps;
  chartPackets.update("none");

  chartBytes.data.labels = labels;
  chartBytes.data.datasets[0].data = bps;
  chartBytes.update("none");

  const proto = state.protocol_breakdown || {};
  chartProto.data.datasets[0].data = [proto.TCP || 0, proto.UDP || 0, proto.ICMP || 0];
  chartProto.update("none");

  const ports = state.top_dst_ports || [];
  chartPorts.data.labels = ports.map(p => `:${p.port}`);
  chartPorts.data.datasets[0].data = ports.map(p => p.bytes);
  chartPorts.update("none");

  renderTalkers(state.top_talkers || []);
  renderBaseline(state.baseline || {});
  renderAlerts(alerts);
}

setInterval(tick, POLL_MS);
tick();
