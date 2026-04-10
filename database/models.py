from __future__ import annotations

from datetime import datetime

from database.db import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    input_type = db.Column(db.String(20), nullable=False)  # url|email|domain|unknown
    raw_input = db.Column(db.Text, nullable=False)

    prediction = db.Column(db.String(16), nullable=False)  # phishing|safe
    confidence = db.Column(db.Float, nullable=False)  # 0..1
    risk_level = db.Column(db.String(16), nullable=False)  # low|medium|high
    threat_score = db.Column(db.Integer, nullable=False)  # 0..100

    # JSON blobs (stored as text for portability)
    reasons_json = db.Column(db.Text, nullable=True)
    highlights_json = db.Column(db.Text, nullable=True)
    intel_json = db.Column(db.Text, nullable=True)
    meta_json = db.Column(db.Text, nullable=True)

