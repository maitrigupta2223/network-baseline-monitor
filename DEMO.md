# DEMO — Network Baseline Monitor

A simple, no-stress 5-minute demo. **Simulator mode only** — no admin
rights, no terminal commands during the demo, no network setup. You
press one button, then talk while the screen does the work.

---

## What the simulator does (so you understand what you're showing)

The simulator is a built-in "fake network". When you start the program,
it generates traffic that looks like a real corporate network:

- **Background:** ~60 packets/sec of normal browsing traffic from a
  pool of internal IPs (192.168.x.x) to common services like Google,
  Cloudflare, and DNS. This trains the baseline.
- **At ~40s:** the simulator injects a **port scan** — one attacker IP
  probes 80 ports on one of your internal hosts.
- **At ~80s:** the simulator injects a **DDoS attack** — 400 packets
  from many fake source IPs slam one internal host.
- **At ~125s:** the simulator injects a **data exfiltration** — one
  internal host sends 12 MB to an external IP.

Each attack should produce **one alert** in the dashboard. After that,
the system stays quiet for several minutes — clean, readable feed.

You don't run any commands. The simulator does everything for you.

---

## The night before — 2-minute dry run

Just confirm it works on the demo computer:

1. Double-click **`run.bat`** (Windows) or run **`./run.sh`** (Mac/Linux).
2. Open **<http://127.0.0.1:5050/>** in a browser.
3. Wait ~2 minutes. You should see:
   - Status pill turns from `training` → `monitoring` after ~30s.
   - One **port-scan** alert around the 40s mark.
   - One **DDoS** alert around the 80s mark (and possibly one
     `Statistical anomaly` alert at the same time — that's fine, it
     just confirms two detectors caught the same event).
   - One **data exfiltration** alert around the 125s mark.
4. Stop with `Ctrl+C` in the terminal.

If those four things happened, you're 100% ready.

---

## The day of — what to do, in order

### Step 1 — Open the program

| OS | Action |
|----|--------|
| Windows | double-click **`run.bat`** in the project folder |
| macOS / Linux | run **`./run.sh`** in a Terminal opened in the project folder |

A black window opens and prints a few lines ending with:
```
[boot] dashboard:  http://127.0.0.1:5050/
```

### Step 2 — Open the dashboard

In a browser, go to **<http://127.0.0.1:5050/>**.

You'll see the dashboard. Don't touch anything. Just talk.

### Step 3 — Talk while the system runs (~5 minutes)

Use the script below. The numbers on the left are minutes from when you
opened the dashboard. Practise it once and you'll have it down.

---

## The exact talking script

### **0:00 — Opening line**

> *"Good morning, sir/ma'am. My project is the **Network Baseline
> Monitor for Anomaly Detection**. The goal is to detect cyber attacks
> on a network in real time, **without** needing prior knowledge of
> the attack — using statistical analysis of network traffic."*

### **0:10 — Walk through the screen**

Point at each section as you describe it:

> *"At the top — packets per second, bytes per second, total flows
> seen, unique IPs, and alerts by severity. These update every second.*
>
> *The big chart is traffic over time — the blue line is what's
> actually happening on the network.*
>
> *Below that — protocol breakdown (TCP, UDP, ICMP), top destination
> ports, and top source IPs.*
>
> *And on the right is the alerts feed. It's empty right now because
> the system is still **learning what normal looks like** — that's the
> orange `training` badge at the top."*

### **0:30 — Status flips to "monitoring"**

The status pill turns green. A dashed purple line and faint band appear
on the main chart.

> *"It's done learning. The dashed purple line is the **mean** —
> normal traffic is about 60 packets per second. The shaded band
> around it is **±3 standard deviations** — anywhere outside that
> is statistically anomalous. From now on, anything weird gets
> flagged."*

### **0:45 — First attack: PORT SCAN appears**

A red alert pops up in the feed. Point at it.

> *"There — a port-scan attack. The system caught it because one
> source IP touched **80 different destination ports** on one target
> within a few seconds. That's exactly what a hacker does when
> mapping a network for vulnerabilities. The system didn't need to
> know what nmap is — it caught the **shape** of the traffic."*

### **1:25 — Second attack: DDoS**

The packets-per-second chart jumps way above the purple band, and a
DDoS alert fires. (You may also see one statistical anomaly alert at
the same moment — that's the z-score detector confirming it
independently.)

> *"Now — a Distributed Denial of Service attack. Hundreds of fake
> source IPs are flooding one of my servers. Notice **two detectors
> fired at once** — the signature detector recognised the DDoS
> pattern, and the statistical detector independently saw that
> traffic was 20+ standard deviations above the baseline. This
> redundancy is what makes the system reliable."*

### **2:10 — Third attack: DATA EXFILTRATION**

The bytes-per-second chart spikes; an exfil alert fires.

> *"Finally — data exfiltration. An internal computer is sending
> megabytes to an unknown external IP. This is what a corporate data
> breach looks like. The system distinguishes 'internal' from
> 'external' using the standard private-IP ranges defined in
> RFC 1918."*

### **2:30 — Closing**

Point at the alerts tile (top-right corner) showing the count.

> *"In about 2 minutes, the system caught three completely different
> cyber attacks — using simple statistics, no machine learning,
> running on a regular laptop. Thank you."*

Stop. Smile. Wait for questions.

---

## Likely questions (with prepared answers)

### Q: How is this different from antivirus?

**"Antivirus matches known signatures — it can only catch attacks
someone has already documented. My system learns what's normal on
this specific network and alerts on anything different — so it can
catch brand-new attacks that have never been seen before."**

### Q: Why not use machine learning?

**"ML needs lots of training data, lots of compute, and the alerts
are hard to explain to a human. My system learns in 30 seconds, runs
on any laptop, and every alert comes with a clear reason like
'packets is 18 standard deviations above mean'. Explainability
matters in real security operations."**

### Q: Why z-score = 3?

**"In a normal distribution, 99.7% of values fall within ±3 standard
deviations. So anything beyond that has less than a 0.3% chance of
being normal — strong signal it's an anomaly."**

### Q: What if normal traffic varies through the day?

**"That's called concept drift. My baseline is a rolling window of
the last 3 minutes of clean traffic, so it continuously adapts.
A future improvement would be hour-of-day modelling, recommended
in paper-3 of my literature survey."**

### Q: Won't an ongoing attack poison the baseline?

**"No — anomalous windows are excluded by design. Only clean
windows update the baseline. So a long attack can't disguise
itself as the new normal."**

### Q: Did you test it?

**"Yes — there are 10 unit tests covering baseline math, window
aggregation, and each detector. All pass."**
*(If they want proof: open a new terminal in the project folder,
run `python -m unittest discover tests -v`.)*

### Q: Is this fake data or real?

**"For a controlled demo I use a built-in traffic simulator so the
attacks fire at predictable times. The same code also supports live
packet capture from the Wi-Fi card using Scapy — that's the
`--mode live` option. I chose the simulator for the demo so we
don't depend on whatever the network is doing right now."**

---

## If something breaks during the demo

Stay calm.

| Problem | Fix |
|---------|-----|
| Browser shows "can't reach 127.0.0.1:5050" | Refresh. If still broken, look at the terminal — there's likely an error message. Most common: port already in use → restart with `python main.py --port 5051` and use that URL instead. |
| Status stays on "training" forever | Restart: Ctrl+C in the terminal, then `run.bat` again. |
| No alerts appear after 2 minutes | Wait another 30 seconds. If still nothing, refresh the browser. The alerts ARE firing — the dashboard might just be lagging. |
| Charts look frozen | Refresh the browser tab. Data is still being collected; it's just the display. |
| Laptop battery dies | Plug in. (Always demo plugged in.) |

---

## One-page cheat sheet

```
1. Double-click run.bat
2. Open http://127.0.0.1:5050/
3. Wait 30s for the green "monitoring" badge.
4. ~40s   → port scan alert
5. ~80s   → DDoS alert
6. ~125s  → data exfiltration alert
7. Point at the alerts tile, say the closing line.
8. Done — wait for questions.
```

That's the whole demo. You don't type anything. You don't need internet.
You don't need admin rights. Just one click, one browser tab, and
talking. You've got this.
