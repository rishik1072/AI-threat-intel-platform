from __future__ import annotations

import json
import os
import tempfile

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas


def export_scan_pdf(scan) -> str:
    """
    Creates a simple PDF report for a scan.
    Returns a filesystem path to the PDF (temporary file).
    """
    fd, path = tempfile.mkstemp(prefix=f"scan_{scan.id}_", suffix=".pdf")
    os.close(fd)

    c = canvas.Canvas(path, pagesize=letter)
    w, h = letter

    x = 0.75 * inch
    y = h - 0.9 * inch

    def line(txt: str, dy: float = 14):
        nonlocal y
        c.drawString(x, y, txt[:140])
        y -= dy
        if y < 0.9 * inch:
            c.showPage()
            y = h - 0.9 * inch

    line("AI Threat Intelligence & Phishing Detection Platform")
    line(f"Scan ID: {scan.id}")
    line(f"Created: {scan.created_at.isoformat()}Z")
    line(f"Type: {scan.input_type}")
    line("")
    line(f"Prediction: {scan.prediction.upper()}")
    line(f"Confidence: {scan.confidence:.3f}")
    line(f"Risk level: {scan.risk_level.upper()}")
    line(f"Threat score: {scan.threat_score}/100")
    line("")
    line("Input:")
    for chunk in (scan.raw_input or "").splitlines()[:10]:
        line(f"  {chunk}")
    if len((scan.raw_input or "").splitlines()) > 10:
        line("  ...")

    line("")
    line("Reasons:")
    reasons = json.loads(scan.reasons_json or "[]")
    for r in reasons[:12]:
        title = r.get("title") or "Reason"
        detail = r.get("detail") or ""
        line(f"- {title}")
        if detail:
            line(f"  {detail}")

    intel = json.loads(scan.intel_json or "{}")
    if intel:
        line("")
        line("Threat intelligence:")
        line(f"- Status: {intel.get('status', 'unknown')}")
        line(f"- Summary: {intel.get('summary', '')}")

    c.save()
    return path

