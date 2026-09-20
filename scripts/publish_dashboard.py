#!/usr/bin/env python3
"""
Generates an HTML dashboard from lab evidence for GitHub Pages.
"""

import json
import os
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
    lab6 = load_json("lab6_migration_roadmap.json")

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
        status = "complete" if s.get("failed", 0) == 0 else "warning"
        labs_status.append({
            "name": "Lab 2: Algorithm Testing",
            "status": status,
            "metrics": [
                f"{s.get('passed', 0)} passed",
                f"{s.get('failed', 0)} failed",
                f"{s.get('total', 0)} total"
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
        phases = lab6.get("phases", [])
        milestones = sum(len(p.get("milestones", [])) for p in phases)
        labs_status.append({
            "name": "Lab 6: Migration Roadmap",
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
        bg = "#28a745" if lab["status"] == "complete" else "#ffc107"
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
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a237e; margin-bottom: 5px; }}
        h2 {{ color: #283593; margin: 30px 0 15px 0; border-bottom: 2px solid #3949ab;
              padding-bottom: 8px; }}
        .subtitle {{ color: #666; margin-bottom: 20px; }}
        .cards {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0;
                background: white; border-radius: 8px; overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th {{ background: #1a237e; color: white; padding: 12px 15px;
             text-align: left; font-size: 0.9em; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #eee; font-size: 0.9em; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px;
                 font-size: 0.8em; font-weight: bold; }}
        .footer {{ margin-top: 40px; padding: 20px; text-align: center;
                  color: #999; font-size: 0.85em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 PQC + PCI-DSS Migration Dashboard</h1>
        <p class="subtitle">
            Post-Quantum Cryptography Migration Evidence | 
            NIST FIPS 203/204/205 | PCI-DSS v4.0 |
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </p>

        <h2>📊 Lab Status</h2>
        <div class="cards">{cards_html}</div>

        <h2>🔬 Algorithm Test Results (Lab 2)</h2>
        <table>
            <tr>
                <th>Test</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
            {alg_rows if alg_rows else '<tr><td colspan="3">Lab 2 data not available</td></tr>'}
        </table>

        <h2>📋 Cryptographic Inventory (Lab 4)</h2>
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

        <h2>⚛️ BB84 QKD Experiments (Lab 5)</h2>
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

        <div class="footer">
            <p>PQC-PCI-DSS Migration Lab | 
               Built with GitHub Actions | 
               Evidence retained for 365 days</p>
            <p>NIST FIPS 203 (ML-KEM) | FIPS 204 (ML-DSA) | FIPS 205 (SLH-DSA)</p>
        </div>
    </div>
</body>
</html>"""

    index_path = DASHBOARD_DIR / "index.html"
    with open(index_path, "w") as f:
        f.write(html)

    print(f"✓ Dashboard: {index_path}")


if __name__ == "__main__":
    generate_dashboard()