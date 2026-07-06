# Network Baseline Monitor for Anomaly Detection

**Author:** Maitri Gupta · MSc Cybersecurity · A869131524026
**Guide:** Dr. Vignesh Ramamoorthy H
**Institution:** Amity Institute of Information Technology

A lightweight, real-time network monitoring system that learns a statistical
baseline of normal traffic and flags deviations that may indicate cyber
attacks — including **port scans**, **DDoS** patterns, and
**data exfiltration**. Ships with a live web dashboard, an SQLite alert log,
and both a synthetic-traffic simulator (no privileges required) and a
real-packet capture mode (Scapy).

> **First time here?**
> - Setting up on a new computer — see [`SETUP.md`](SETUP.md).
> - Running the demo for an examiner — see [`DEMO.md`](DEMO.md).
> - The TL;DR: `python -m venv .venv && .venv/bin/pip install -r requirements.txt && python main.py` then open <http://127.0.0.1:5050/>.

---

## 1. Abstract

Modern enterprise networks face a steady stream of cyber threats — many of
which never match a known signature. This project implements a baseline-driven
anomaly detection system that captures network traffic in real time, derives
per-window features (packet rate, byte rate, unique IPs, port spread,
protocol mix), maintains a rolling statistical baseline of "normal" behaviour,
and raises alerts when current traffic deviates significantly from that
baseline. Statistical detection (z-score over the learned mean/standard
deviation) is combined with three lightweight signature detectors so that
common attack patterns are flagged with high confidence even before warm-up is
complete.

## 2. Problem Statement

* Signature-based IDS cannot detect previously unknown attacks.
* Heavyweight ML-based IDS is expensive to train and difficult to deploy.
* There is room for a **lightweight, real-time, statistically-grounded**
  anomaly detector that students and small teams can run on commodity hardware.

## 3. Objectives

| # | Objective | Implementation |
|---|-----------|----------------|
| 1 | Capture real-time traffic | `monitor/capture.py` (Scapy) + `monitor/simulator.py` |
| 2 | Extract IP / port / protocol features | `monitor/features.py` |
| 3 | Build a baseline of normal behaviour | `monitor/baseline.py` |
| 4 | Detect anomalies using statistical methods | `monitor/detector.py` (z-score) |
| 5 | Generate alerts for suspicious activity | `monitor/alerts.py` + SQLite |
| 6 | Visualise traffic patterns | Flask + Chart.js dashboard |

## 4. Architecture

```
                  ┌───────────────┐
                  │   Source      │  ── simulator (default)
                  │ (flow stream) │  ── live capture (scapy, sudo)
                  └──────┬────────┘
                         │  Flow records
                         ▼
                ┌──────────────────┐
                │ WindowAggregator │   1-second feature windows
                └──────┬───────────┘
                       │  Window
       ┌───────────────┼────────────────┐
       ▼                                 ▼
┌────────────────┐             ┌────────────────────┐
│  Statistical   │             │  Signature         │
│  baseline      │◀── feedback │  detectors         │
│  (mean/σ)      │   (clean    │  · port scan       │
│  z-score check │    windows) │  · DDoS            │
└──────┬─────────┘             │  · data exfil      │
       │                       └────────┬───────────┘
       └─────────────┬──────────────────┘
                     ▼
              ┌──────────────┐         ┌──────────────┐
              │ AlertManager │ ──────▶ │  SQLite DB   │
              │ (dedup)      │         └──────────────┘
              └──────┬───────┘
                     ▼
              ┌──────────────┐
              │ Flask + JS   │   live dashboard, charts, alert feed
              └──────────────┘
```

### Pipeline (one tick)

1. **Source** emits raw `Flow` records (one per packet).
2. **WindowAggregator** buckets them into 1-second windows.
3. On each completed window:
   1. The four detectors examine it (statistical + 3 signatures).
   2. If **no** detection fires, the window's metrics are added to the
      baseline (this prevents attack traffic from poisoning the baseline).
   3. New detections are submitted to the **AlertManager**, which dedupes
      identical alerts within a configurable cooldown window and persists
      them.
4. The Flask dashboard polls `/api/state` every second and re-renders.

## 5. Detection Methodology

### 5.1 Statistical (z-score)

For each metric `m` (packets, bytes, unique src IPs, etc.) the system
maintains a rolling mean `μ_m` and population standard deviation `σ_m`
across the last `N` clean windows. A window is flagged if any monitored
metric satisfies:

```
|x − μ_m| / σ_m   >   Z          (Z = 3 by default)
```

If `|z| > 1.5·Z` the alert is escalated from `warning` to `critical`.

### 5.2 Port-scan signature

For every source IP, the union of distinct destination ports observed
across the last `portscan_window_seconds` (default 10s) is computed. If
that set has at least `portscan_min_ports` (default 20) distinct ports,
the source is reported as a scanner.

### 5.3 DDoS signature

For every destination IP, the union of distinct source IPs and total
packets received in the last `ddos_window_seconds` (default 5s) are
computed. If both `≥ ddos_min_sources` (default 40) **and**
`≥ ddos_min_pps` (default 200) thresholds are met, a DDoS alert is raised.

### 5.4 Data-exfiltration signature

For every (internal_src, external_dst) pair, total outbound bytes within
`exfil_window_seconds` (default 10s) are computed. An alert fires if the
total exceeds an absolute threshold (default 5 MB) **or** is more than
`exfil_bytes_ratio` (default 5×) the baseline mean of per-window bytes.
Internal vs external is decided from the configured RFC1918 CIDRs.

## 6. Project Layout

```
network-baseline-monitor/
├── main.py                  # entry point
├── requirements.txt
├── run.sh                   # one-shot venv + install + run
├── monitor/
│   ├── config.py            # all thresholds / tunables
│   ├── flow.py              # Flow dataclass
│   ├── simulator.py         # synthetic traffic + injected attacks
│   ├── capture.py           # live Scapy capture (optional)
│   ├── features.py          # WindowAggregator + Window
│   ├── baseline.py          # rolling μ/σ
│   ├── detector.py          # z-score + 3 signatures
│   ├── alerts.py            # dedup + persistence wiring
│   ├── store.py             # SQLite layer
│   ├── engine.py            # orchestrates the pipeline
│   ├── app.py               # Flask app + REST endpoints
│   └── utils.py
├── templates/dashboard.html
├── static/
│   ├── app.js               # Chart.js dashboard, polls /api/state
│   └── style.css
├── tests/                   # unittest suite
└── data/                    # SQLite DB created at runtime
```

## 7. Setup & Run

### Quick start (zero privileges, simulator demo)

```bash
cd network-baseline-monitor
./run.sh
# open http://127.0.0.1:5050/
```

`run.sh` creates a virtual environment, installs Flask, and launches
`main.py` in simulator mode. Within ~30 seconds the baseline finishes
warm-up and the system enters **monitoring** mode. Within the first ~2
minutes you should see at least one **port-scan**, one **DDoS**, and one
**exfiltration** alert appear in the live feed (the simulator schedules them).

### Manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Live packet capture (optional)

```bash
pip install scapy
sudo .venv/bin/python main.py --mode live --iface en0
```

`--iface` is required on most systems. `--bpf "ip"` is the default Berkeley
Packet Filter; tighten it (e.g. `tcp port 443`) to focus on a subset of
traffic.

### Configuration

Tune anything in [`monitor/config.py`](monitor/config.py) — z-threshold,
warm-up duration, signature thresholds, internal CIDRs, SQLite path, etc.

### Tests

```bash
python -m unittest discover tests -v
```

The suite exercises the baseline math, window aggregation, and each of the
three signature detectors.

## 8. Dashboard

The dashboard lives at `http://127.0.0.1:5050/` and shows:

* **Status pill** — `training X%` during warm-up, `monitoring` once the
  baseline is established.
* **KPI tiles** — packets/sec, bytes/sec, total flows, unique IPs, alert
  counters by severity.
* **Packets/sec chart** — observed line with the baseline mean overlaid as
  a dashed line and a shaded ±3σ band; anomalous windows are marked with
  red dots.
* **Bytes/sec, protocol mix, top destination ports, top source IPs** — at
  a glance.
* **Live alerts feed** — color-coded by severity with type, time, source
  and a one-line reason.
* **Learned baseline table** — μ, σ and sample count per metric.

## 9. Deliverables Mapped to Synopsis Objectives

| PPT objective              | Where it lives                              |
|----------------------------|---------------------------------------------|
| Capture real-time traffic  | `simulator.py`, `capture.py`                |
| Analyse IP/port/protocol   | `features.py` (Window + WindowAggregator)   |
| Build baseline             | `baseline.py`                               |
| Detect anomalies           | `detector.py`                               |
| Generate alerts            | `alerts.py`, `store.py`                     |
| Visualise traffic patterns | `app.py`, `templates/`, `static/`           |

## 10. Future Work (as per literature survey)

* Adaptive baselines (EWMA / dynamic seasonality) instead of a flat rolling
  window — addresses paper-1 and paper-3 limitations.
* Hybrid statistical + ML detection (paper-2 future work) using a small
  unsupervised model (e.g. Isolation Forest) on top of the same features.
* Encrypted-traffic exfiltration via TLS metadata (paper-9 future work).
* Stealthy slow-rate scan detection by extending the port-scan window
  (paper-10 future work).

## 11. References

The full reference list is in the synopsis presentation. Key sources used to
shape this implementation:

* W. Zhang & J. P. Lazaro, *A Survey on Network Security Traffic Analysis
  and Anomaly Detection Techniques*, 2024.
* X. Yue, *Research on Network Anomaly Traffic Detection System Based on
  Statistical Analysis*, Procedia Computer Science, 2024.
* P. Schummer et al., *Machine Learning-Based Network Anomaly Detection
  System for Real-Time Applications*, Systems, 2024.
* W. Yao et al., *A Lightweight Anomaly Detection Model for Network Traffic
  Using Knowledge Transfer*, 2025.
