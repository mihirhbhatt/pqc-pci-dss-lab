#!/usr/bin/env python3
"""
Generates an HTML dashboard from lab evidence for GitHub Pages.
"""

import json
import os
from html import escape
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "reports"))
DASHBOARD_DIR = REPORTS_DIR / "dashboard"
DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)


def load_json(filename):
    path = EVIDENCE_DIR / filename
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def generate_dashboard():
    """Generate HTML dashboard."""

    lab1 = load_json("lab1_pqc_pcidss_alignment.json")
    lab2 = load_json("lab2_algorithm_test_evidence.json")
    lab3 = load_json("lab3_tls_evidence.json")
    lab4 = load_json("lab4_crypto_inventory.json")
    lab5 = load_json("lab5_bb84_evidence.json")
    lab6 = load_json("lab6_qkd_attack_detection.json")
    lab7 = load_json("lab7_migration_roadmap.json")

    status_colors = {
        "Complete": "#187f70",
        "Skipped": "#d29a2e",
        "Failed": "#c64d47",
        "Missing": "#89958f",
    }
    status_counts = {status: 0 for status in status_colors}
    lab_evidence = [lab1, lab2, lab3, lab4, lab5, lab6, lab7]
    for evidence in lab_evidence:
        if not evidence:
            status = "Missing"
        elif evidence.get("status") == "SKIPPED":
            status = "Skipped"
        elif evidence.get("status") in {"FAIL", "FAILED", "ERROR"} or (
            evidence.get("summary", {}).get("failed", 0) > 0
        ):
            status = "Failed"
        else:
            status = "Complete"
        status_counts[status] += 1

    risk_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    risk_counts = {level: 0 for level in risk_levels}
    if lab4:
        for asset in lab4.get("assets", []):
            risk = asset.get("harvest_now_risk", "").split(" - ", 1)[0].strip()
            if risk in risk_counts:
                risk_counts[risk] += 1

    status_total = sum(status_counts.values())
    gradient_stops = []
    start_percent = 0.0
    for status, count in status_counts.items():
        end_percent = start_percent + (count / status_total * 100 if status_total else 0)
        color = status_colors[status]
        gradient_stops.extend((f"{color} {start_percent:.1f}%", f"{color} {end_percent:.1f}%"))
        start_percent = end_percent
    pie_gradient = ", ".join(gradient_stops) or "#dfe5e1 0% 100%"
    pie_legend = "".join(
        f'<li><span style="--swatch:{status_colors[status]}"></span>'
        f"{escape(status)} <strong>{count}</strong></li>"
        for status, count in status_counts.items()
        if count
    ) or "<li>No lab evidence available</li>"

    max_risk_count = max(risk_counts.values(), default=0) or 1
    risk_rows = "".join(
        f'<div class="bar-row"><span>{escape(level.title())}</span>'
        f'<div class="bar-track"><span style="--bar-width:{count / max_risk_count * 100:.1f}%;'
        f'--bar-color:{color}"></span></div><strong>{count}</strong></div>'
        for level, color in zip(risk_levels, ("#b8433e", "#d4773f", "#d5a33b", "#2b8878"))
        for count in (risk_counts[level],)
    )

    # Build status cards
    labs_status = []

    if lab1:
        labs_status.append({
            "name": "Lab 1: Standards Mapping",
            "status": "complete",
            "metrics": [
                f"{len(lab1.get('alignments', []))} alignments",
                f"{len(lab1.get('algorithm_decisions', []))} decisions"
            ]
        })

    if lab2:
        s = lab2.get("summary", {})
        status = (
            "skipped" if lab2.get("status") == "SKIPPED"
            else "complete" if s.get("failed", 0) == 0
            else "warning"
        )
        labs_status.append({
            "name": "Lab 2: Algorithm Testing",
            "status": status,
            "metrics": [
                lab2.get("reason", "liboqs-python unavailable")
                if status == "skipped"
                else f"{s.get('passed', 0)} passed",
                *([] if status == "skipped" else [
                    f"{s.get('failed', 0)} failed",
                    f"{s.get('total', 0)} total",
                ]),
            ]
        })

    if lab3:
        labs_status.append({
            "name": "Lab 3: TLS Configuration",
            "status": "complete",
            "metrics": [
                f"TLS: {lab3.get('certificates', {}).get('tls_test', {}).get('status', 'unknown')}"
            ]
        })

    if lab4:
        labs_status.append({
            "name": "Lab 4: Crypto Inventory",
            "status": "complete",
            "metrics": [
                f"{lab4.get('total_assets', 0)} assets",
                f"{lab4.get('quantum_vulnerable_assets', 0)} vulnerable",
                f"{lab4.get('quantum_safe_assets', 0)} safe"
            ]
        })

    if lab5:
        exps = lab5.get("experiments", [])
        labs_status.append({
            "name": "Lab 5: BB84 Simulation",
            "status": "complete",
            "metrics": [f"{len(exps)} experiments completed"]
        })

    if lab6:
        trials = lab6.get("trials", [])
        attack_indicators = sum("ATTACK_SUSPECTED" in trial.get("classification", "") for trial in trials)
        labs_status.append({
            "name": "Lab 6: QKD Attack Detection",
            "status": "complete",
            "metrics": [f"{len(trials)} scenarios", f"{attack_indicators} attack indicators"]
        })

    if lab7:
        phases = lab7.get("phases", [])
        milestones = sum(len(p.get("milestones", [])) for p in phases)
        labs_status.append({
            "name": "Lab 7: Migration Roadmap",
            "status": "complete",
            "metrics": [f"{len(phases)} phases", f"{milestones} milestones"]
        })

    # Build algorithm test results table
    alg_rows = ""
    if lab2:
        for r in lab2.get("test_results", []):
            color = "#28a745" if r["status"] == "PASS" else "#dc3545" if r["status"] == "FAIL" else "#6c757d"
            details_str = ""
            if isinstance(r.get("details"), dict):
                details_str = ", ".join(f"{k}={v}" for k, v in r["details"].items()
                                       if isinstance(v, (int, float, str, bool)))
            alg_rows += f"""
            <tr>
                <td>{r['test_name']}</td>
                <td style="color:{color};font-weight:bold">{r['status']}</td>
                <td style="font-size:0.85em">{details_str[:120]}</td>
            </tr>"""

    # Build BB84 results table
    bb84_rows = ""
    if lab5:
        for exp in lab5.get("experiments", []):
            eve_str = "🔴 Yes" if exp.get("eve_present") else "🟢 No"
            detected = "⚠️ Yes" if exp.get("eavesdropper_detected") else "✅ No"
            bb84_rows += f"""
            <tr>
                <td>{exp.get('experiment_id', '')}</td>
                <td>{exp.get('description', '')[:50]}</td>
                <td>{eve_str}</td>
                <td>{exp.get('qber', 0)*100:.2f}%</td>
                <td>{detected}</td>
                <td>{exp.get('final_key_length_bits', 0)} bits</td>
            </tr>"""

    # Build QKD attack-detection evidence table
    qkd_rows = ""
    if lab6:
        for trial in lab6.get("trials", []):
            classification = trial.get("classification", "UNKNOWN")
            response = trial.get("response", "Not specified")
            qkd_rows += f"""
            <tr>
                <td>{escape(trial.get('scenario', ''))}</td>
                <td><strong>{escape(classification)}</strong></td>
                <td>{trial.get('qber', 0) * 100:.2f}%</td>
                <td>{trial.get('sample_size', 0)}</td>
                <td>{escape(trial.get('reason', ''))}</td>
                <td>{escape(response)}</td>
            </tr>"""

    # Build migration roadmap evidence table
    roadmap_rows = ""
    if lab7:
        for phase in lab7.get("phases", []):
            phase_label = (
                f"Phase {phase.get('phase', '')}: {phase.get('name', '')} "
                f"(Days {phase.get('start_day', '')}-{phase.get('end_day', '')})"
            )
            for milestone in phase.get("milestones", []):
                deliverables = "<br>".join(
                    f"- {escape(item)}" for item in milestone.get("deliverables", [])
                )
                acceptance = "<br>".join(
                    f"- {escape(item)}" for item in milestone.get("acceptance_criteria", [])
                )
                rollback = "<br>".join(
                    f"- {escape(item)}" for item in milestone.get("rollback_trigger", [])
                ) or "None specified"
                roadmap_rows += f"""
                <tr>
                    <td>{escape(phase_label)}</td>
                    <td><strong>{escape(milestone.get('milestone_id', ''))}: {escape(milestone.get('name', ''))}</strong><br>
                        Due: {escape(milestone.get('due_date', ''))}<br>
                        Owner: {escape(milestone.get('owner', ''))}</td>
                    <td>{escape(milestone.get('description', ''))}<br><br>{deliverables}</td>
                    <td>{acceptance}</td>
                    <td>{rollback}</td>
                </tr>"""

    # Build inventory table
    inv_rows = ""
    if lab4:
        for asset in lab4.get("assets", [])[:10]:
            risk_color = {
                "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                "MEDIUM": "#ffc107", "LOW": "#28a745"
            }
            risk_level = asset.get("harvest_now_risk", "").split(" — ")[0]
            color = risk_color.get(risk_level, "#6c757d")
            inv_rows += f"""
            <tr>
                <td>{asset.get('asset_id', '')}</td>
                <td>{asset.get('system_name', '')[:30]}</td>
                <td>{asset.get('key_exchange', 'N/A')[:20]}</td>
                <td style="color:{color};font-weight:bold">{risk_level}</td>
                <td>{asset.get('priority_score', 0)}</td>
                <td>{asset.get('migration_target', '')[:35]}</td>
            </tr>"""

    # Status cards HTML
    cards_html = ""
    for lab in labs_status:
        bg = {
            "complete": "#187f70",
            "warning": "#c64d47",
            "skipped": "#9a721f",
        }.get(lab["status"], "#89958f")
        metrics_html = "<br>".join(lab["metrics"])
        cards_html += f"""
        <div style="background:{bg};color:white;padding:20px;border-radius:8px;
                    margin:10px;flex:1;min-width:200px">
            <h3 style="margin:0 0 10px 0">{lab['name']}</h3>
            <p style="margin:0;font-size:0.9em">{metrics_html}</p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQC + PCI-DSS Migration Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <style>
        :root {{ color-scheme: light; --ink: #1c302b; --muted: #65756f;
                 --line: #dce5e0; --paper: #ffffff; --canvas: #eef3f0; }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: "Segoe UI", sans-serif; background: var(--canvas);
               color: var(--ink); line-height: 1.55; }}
        .container {{ max-width: 1240px; margin: 0 auto; padding: 34px 24px 48px; }}
        .masthead {{ border-bottom: 1px solid var(--line); padding-bottom: 20px; }}
        h1 {{ font-size: 30px; line-height: 1.2; margin-bottom: 8px; }}
        h2 {{ font-size: 17px; line-height: 1.3; }}
        .subtitle {{ color: var(--muted); font-size: 14px; }}
        .cards {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 18px 0 30px; }}
        .cards > div {{ border-radius: 6px; margin: 0 !important; min-width: 180px !important;
                        padding: 14px 16px !important; flex: 1 1 180px; }}
        .cards h3 {{ font-size: 14px; }}
        .charts {{ display: grid; grid-template-columns: minmax(0, .9fr) minmax(0, 1.1fr);
                   gap: 24px; margin: 24px 0 36px; }}
        .chart-panel {{ min-width: 0; background: var(--paper); border: 1px solid var(--line);
                        border-radius: 6px; padding: 20px 22px; }}
        .chart-heading {{ display: flex; justify-content: space-between; gap: 12px;
                          align-items: baseline; margin-bottom: 14px; }}
        .chart-heading span {{ color: var(--muted); font-size: 13px; }}
        .chart-stage {{ height: 260px; position: relative; }}
        .chart-stage canvas {{ display: none; width: 100% !important; height: 100% !important; }}
        .chart-stage.is-charted canvas {{ display: block; }}
        .chart-stage.is-charted .chart-fallback {{ display: none; }}
        .pie-fallback {{ height: 174px; width: 174px; border-radius: 50%; margin: 4px auto 14px;
                         display: grid; place-items: center; position: relative; }}
        .pie-fallback::after {{ content: ""; position: absolute; inset: 30%; border-radius: 50%;
                               background: var(--paper); }}
        .pie-fallback strong {{ position: relative; z-index: 1; text-align: center; font-size: 20px; }}
        .pie-fallback strong small {{ display: block; color: var(--muted); font-size: 11px;
                                     font-weight: 500; }}
        .chart-legend {{ list-style: none; display: flex; flex-wrap: wrap; justify-content: center;
                         gap: 8px 16px; color: var(--muted); font-size: 12px; }}
        .chart-legend li {{ display: flex; align-items: center; gap: 6px; }}
        .chart-legend li span {{ width: 9px; height: 9px; border-radius: 50%;
                                 background: var(--swatch); }}
        .chart-legend strong {{ color: var(--ink); }}
        .bar-fallback {{ height: 100%; display: flex; flex-direction: column; justify-content: center;
                         gap: 17px; padding: 12px 2px; }}
        .bar-row {{ display: grid; grid-template-columns: 90px minmax(60px, 1fr) 28px;
                    align-items: center; gap: 12px; font-size: 13px; }}
        .bar-row > span {{ color: var(--muted); }}
        .bar-row strong {{ text-align: right; }}
        .bar-track {{ height: 13px; background: #edf2ef; border-radius: 2px; overflow: hidden; }}
        .bar-track span {{ display: block; width: var(--bar-width); height: 100%;
                           background: var(--bar-color); border-radius: 2px; }}
        .section-title {{ margin: 30px 0 12px; }}
        .table-wrap {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin: 12px 0 28px;
                background: var(--paper); border: 1px solid var(--line); }}
        th {{ background: #284b40; color: white; padding: 11px 13px;
             text-align: left; font-size: 12px; white-space: nowrap; }}
        td {{ padding: 10px 13px; border-bottom: 1px solid var(--line); font-size: 13px;
             vertical-align: top; }}
        tr:hover {{ background: #f6f9f7; }}
        .footer {{ margin-top: 38px; padding-top: 16px; border-top: 1px solid var(--line);
                  color: var(--muted); font-size: 12px; }}
        @media (max-width: 720px) {{
            .container {{ padding: 22px 14px 36px; }}
            h1 {{ font-size: 25px; }}
            .charts {{ grid-template-columns: 1fr; gap: 14px; }}
            .chart-panel {{ padding: 17px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="masthead">
        <h1>PQC + PCI-DSS Migration Dashboard</h1>
        <p class="subtitle">
            Post-Quantum Cryptography Migration Evidence | 
            NIST FIPS 203/204/205 | PCI-DSS v4.0 |
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </p>
        </header>

        <h2 class="section-title">Lab Status</h2>
        <div class="cards">{cards_html}</div>

        <section class="charts" aria-label="Lab and risk summaries">
            <article class="chart-panel">
                <div class="chart-heading"><h2>Lab execution</h2><span>{status_total} labs</span></div>
                <div class="chart-stage">
                    <canvas id="lab-status-chart" role="img" aria-label="Pie chart of lab statuses"></canvas>
                    <div class="chart-fallback">
                        <div class="pie-fallback" style="background:conic-gradient({pie_gradient})">
                            <strong>{status_total}<small>labs</small></strong>
                        </div>
                        <ul class="chart-legend">{pie_legend}</ul>
                    </div>
                </div>
            </article>
            <article class="chart-panel">
                <div class="chart-heading"><h2>Assets by quantum risk</h2>
                    <span>{sum(risk_counts.values())} inventoried</span></div>
                <div class="chart-stage">
                    <canvas id="risk-chart" role="img" aria-label="Bar chart of assets by quantum risk"></canvas>
                    <div class="bar-fallback">{risk_rows or '<p class="subtitle">No inventory evidence available</p>'}</div>
                </div>
            </article>
        </section>

        <h2 class="section-title">Algorithm Test Results (Lab 2)</h2>
        <div class="table-wrap">
        <table>
            <tr>
                <th>Test</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
            {alg_rows if alg_rows else '<tr><td colspan="3">Lab 2 data not available</td></tr>'}
        </table>
        </div>

        <h2 class="section-title">Cryptographic Inventory (Lab 4)</h2>
        <div class="table-wrap">
        <table>
            <tr>
                <th>ID</th>
                <th>System</th>
                <th>Key Exchange</th>
                <th>Quantum Risk</th>
                <th>Score</th>
                <th>Migration Target</th>
            </tr>
            {inv_rows if inv_rows else '<tr><td colspan="6">Lab 4 data not available</td></tr>'}
        </table>
        </div>

        <h2 class="section-title">BB84 QKD Experiments (Lab 5)</h2>
        <div class="table-wrap">
        <table>
            <tr>
                <th>#</th>
                <th>Description</th>
                <th>Eve Present</th>
                <th>QBER</th>
                <th>Detected</th>
                <th>Key Length</th>
            </tr>
            {bb84_rows if bb84_rows else '<tr><td colspan="6">Lab 5 data not available</td></tr>'}
        </table>
        </div>

        <h2 class="section-title">QKD Attack Detection Details (Lab 6)</h2>
        <p class="subtitle">Each observation maps to a protocol action. QBER is a signal; the response should also consider channel health and key availability.</p>
        <div class="table-wrap">
        <table>
            <tr>
                <th>Scenario</th>
                <th>Classification</th>
                <th>QBER</th>
                <th>Sample Bits</th>
                <th>Why</th>
                <th>Required Response</th>
            </tr>
            {qkd_rows if qkd_rows else '<tr><td colspan="6">Lab 6 data not available</td></tr>'}
        </table>
        </div>

        <h2 class="section-title">Migration Roadmap Details (Lab 7)</h2>
        <p class="subtitle">Use the owner, deliverables, acceptance criteria, and rollback triggers to turn each milestone into the next execution step.</p>
        <div class="table-wrap">
        <table>
            <tr>
                <th>Phase</th>
                <th>Milestone / Owner</th>
                <th>Action and Deliverables</th>
                <th>Acceptance Criteria</th>
                <th>Rollback Triggers</th>
            </tr>
            {roadmap_rows if roadmap_rows else '<tr><td colspan="5">Lab 7 data not available</td></tr>'}
        </table>
        </div>

        <div class="footer">
            <p>PQC-PCI-DSS Migration Lab | 
               Built with GitHub Actions | 
               Evidence retained for 365 days</p>
            <p>NIST FIPS 203 (ML-KEM) | FIPS 204 (ML-DSA) | FIPS 205 (SLH-DSA)</p>
        </div>
    </div>
    <script>
        const statusStage = document.getElementById("lab-status-chart").parentElement;
        const riskStage = document.getElementById("risk-chart").parentElement;
        if (typeof Chart !== "undefined") {{
            new Chart(document.getElementById("lab-status-chart"), {{
                type: "pie",
                data: {{
                    labels: {json.dumps(list(status_counts))},
                    datasets: [{{
                        data: {json.dumps(list(status_counts.values()))},
                        backgroundColor: {json.dumps(list(status_colors.values()))},
                        borderColor: "#ffffff",
                        borderWidth: 3,
                        hoverOffset: 8,
                    }}],
                }},
                options: {{
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: "bottom", labels: {{ usePointStyle: true, padding: 18 }} }} }},
                }},
            }});
            new Chart(document.getElementById("risk-chart"), {{
                type: "bar",
                data: {{
                    labels: {json.dumps([level.title() for level in risk_levels])},
                    datasets: [{{
                        data: {json.dumps([risk_counts[level] for level in risk_levels])},
                        backgroundColor: ["#b8433e", "#d4773f", "#d5a33b", "#2b8878"],
                        borderRadius: 3,
                        maxBarThickness: 30,
                    }}],
                }},
                options: {{
                    indexAxis: "y",
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{
                        x: {{ beginAtZero: true, ticks: {{ precision: 0 }}, grid: {{ color: "#e8eeea" }} }},
                        y: {{ grid: {{ display: false }} }},
                    }},
                }},
            }});
            statusStage.classList.add("is-charted");
            riskStage.classList.add("is-charted");
        }}
    </script>
</body>
</html>"""

    index_path = DASHBOARD_DIR / "index.html"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✓ Dashboard: {index_path}")


if __name__ == "__main__":
    generate_dashboard()