"""HTML reporting for Mini-CSPM execution results."""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from models import ExecutionResult, Finding
from settings import Settings
import s3io


@dataclass
class _Card:
    title: str
    value: str
    subtitle: str


def render_html(result: ExecutionResult, settings: Settings) -> str:
    """Render an HTML report string containing scorecards, sparkline, and summaries."""
    summary = result.summary
    cards = [
        _Card("Overall Score", f"{result.score.weighted}", "Weighted percentage"),
        _Card("Pass", str(summary.PASS), "Checks passing"),
        _Card("Fail", str(summary.FAIL), "Checks failing"),
        _Card("Warn", str(summary.WARN), "Checks warning"),
    ]
    sparkline = _build_sparkline([summary.PASS, summary.WARN, summary.FAIL])
    top_failures = _top_failures(result.findings)
    remediation_summary = _collect_remediation_summary(result.findings)
    findings_table = _build_findings_table(result.findings)

    cards_html = "\n".join(
        f"""
        <div class="card">
          <h3>{html.escape(card.title)}</h3>
          <span class="value">{html.escape(card.value)}</span>
          <span class="subtitle">{html.escape(card.subtitle)}</span>
        </div>
        """
        for card in cards
    )

    top_failure_rows = "\n".join(
        f"""
        <tr>
          <td>{html.escape(finding.id)}</td>
          <td>{html.escape(finding.title)}</td>
          <td>{html.escape(finding.severity)}</td>
          <td>{html.escape(finding.service)}</td>
          <td>{html.escape(", ".join(finding.resource_ids))}</td>
        </tr>
        """
        for finding in top_failures
    ) or '<tr><td colspan="5">All controls are passing.</td></tr>'

    remediation_rows = "\n".join(
        f"""
        <tr>
          <td>{html.escape(item["control"])}</td>
          <td>{html.escape(item["action"])}</td>
          <td>{html.escape(item["mode"])}</td>
          <td>{'Yes' if item['applied'] else 'No'}</td>
          <td>{html.escape(item['message'])}</td>
        </tr>
        """
        for item in remediation_summary
    ) or '<tr><td colspan="5">No remediation actions executed.</td></tr>'

    html_doc = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Mini-CSPM Report - {html.escape(result.account_id)}</title>
    <style>
      body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
        padding: 24px;
        background-color: #f9fafb;
        color: #111827;
      }}
      h1 {{
        margin-bottom: 4px;
      }}
      .meta {{
        color: #6b7280;
        margin-bottom: 24px;
      }}
      .cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
      }}
      .card {{
        background: white;
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.08);
      }}
      .card h3 {{
        margin: 0;
        font-size: 14px;
        color: #6b7280;
        text-transform: uppercase;
      }}
      .card .value {{
        display: block;
        font-size: 32px;
        font-weight: 700;
        color: #0f172a;
      }}
      .card .subtitle {{
        font-size: 12px;
        color: #9ca3af;
      }}
      .sparkline {{
        background: white;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 24px;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.08);
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 24px;
        background: white;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.08);
      }}
      th, td {{
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid #e5e7eb;
      }}
      th {{
        background-color: #f3f4f6;
        text-transform: uppercase;
        font-size: 12px;
        letter-spacing: 0.05em;
        color: #6b7280;
      }}
      tr:last-child td {{
        border-bottom: none;
      }}
      .findings-table {{
        overflow-x: auto;
      }}
    </style>
  </head>
  <body>
    <header>
      <h1>Mini-CSPM Execution Report</h1>
      <p class="meta">
        Account: {html.escape(result.account_id)} · Region: {html.escape(result.region)} · Timestamp: {result.timestamp.isoformat()}
      </p>
    </header>
    <section class="cards">
      {cards_html}
    </section>
    <section class="sparkline">
      <h2>Status Trend</h2>
      <p>Distribution of PASS, WARN, FAIL checks</p>
      {sparkline}
    </section>
    <section>
      <h2>Top Failing Controls</h2>
      <table>
        <thead>
          <tr>
            <th>Control</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Service</th>
            <th>Resources</th>
          </tr>
        </thead>
        <tbody>
          {top_failure_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Auto Remediation Summary</h2>
      <table>
        <thead>
          <tr>
            <th>Control</th>
            <th>Action</th>
            <th>Mode</th>
            <th>Applied</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {remediation_rows}
        </tbody>
      </table>
    </section>
    <section class="findings-table">
      <h2>All Findings</h2>
      {findings_table}
    </section>
  </body>
</html>
"""
    return html_doc


def _top_failures(findings: Sequence[Finding]) -> List[Finding]:
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    failures = [finding for finding in findings if finding.status == "FAIL"]
    failures.sort(key=lambda f: (severity_rank.get(f.severity, 99), f.title))
    return failures[:5]


def _collect_remediation_summary(findings: Iterable[Finding]) -> List[dict]:
    items: List[dict] = []
    for finding in findings:
        remediations = finding.evidence.get("remediations") if hasattr(finding, "evidence") else None
        if not remediations:
            continue
        for entry in remediations:
            items.append(
                {
                    "control": finding.id,
                    "action": entry.get("action", ""),
                    "mode": entry.get("mode", ""),
                    "applied": bool(entry.get("applied")),
                    "message": entry.get("message", ""),
                }
            )
    return items


def _build_sparkline(values: Sequence[int]) -> str:
    values = list(values)
    if not values:
        values = [0]
    max_value = max(values) or 1
    height = 40
    width = 120
    step = width / (len(values) - 1) if len(values) > 1 else 0
    points = []
    for idx, value in enumerate(values):
        x = idx * step
        y = height - (value / max_value) * (height - 10) - 5
        points.append(f"{x:.2f},{y:.2f}")
    points_str = " ".join(points)
    labels = ["PASS", "WARN", "FAIL"]
    label_spans = "".join(
        f'<span>{label}: {values[idx] if idx < len(values) else 0}</span>' for idx, label in enumerate(labels)
    )
    return f"""
      <svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" aria-hidden="true">
        <polyline fill="none" stroke="#2563eb" stroke-width="2" points="{points_str}"></polyline>
        <circle cx="{points[0].split(',')[0]}" cy="{points[0].split(',')[1]}" r="2" fill="#1d4ed8"></circle>
        <circle cx="{points[-1].split(',')[0]}" cy="{points[-1].split(',')[1]}" r="2" fill="#1d4ed8"></circle>
      </svg>
      <div class="labels">{label_spans}</div>
    """


def _build_findings_table(findings: Sequence[Finding]) -> str:
    rows = []
    for finding in findings:
        notes = finding.evidence.get("note") if hasattr(finding, "evidence") else ""
        rows.append(
            f"""
            <tr>
              <td>{html.escape(finding.id)}</td>
              <td>{html.escape(finding.title)}</td>
              <td>{html.escape(finding.cis)}</td>
              <td>{html.escape(finding.service)}</td>
              <td>{html.escape(finding.severity)}</td>
              <td>{html.escape(finding.status)}</td>
              <td>{html.escape(", ".join(finding.resource_ids))}</td>
              <td>{html.escape(notes or "")}</td>
            </tr>
            """
        )
    if not rows:
        rows.append('<tr><td colspan="8">No findings recorded.</td></tr>')
    return f"""
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>CIS</th>
          <th>Service</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Resources</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
    """


def write_html(result: ExecutionResult, settings: Settings) -> str:
    """Render the HTML report and upload it to S3."""
    body = render_html(result=result, settings=settings)
    key = s3io.build_report_key(settings.html_prefix, result, "html")
    s3io.put_object(key=key, body=body.encode("utf-8"), content_type="text/html")
    return key
