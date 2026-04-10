import json
from datetime import datetime

from flask import Blueprint, jsonify, request, send_file
from sqlalchemy import desc

from database.db import db
from database.models import Scan
from utils.async_jobs import get as get_job
from utils.async_jobs import attach_scan_id
from utils.async_jobs import submit as submit_job
from utils.exporting import export_scan_pdf
from utils.scanner import scan_input
from utils.validation import normalize_and_classify_input
from utils.chatbot import explain_scan_naturally

api_bp = Blueprint("api", __name__)


def _persist_scan(norm: dict, result: dict) -> Scan:
    scan = Scan(
        input_type=norm["input_type"],
        raw_input=norm["normalized_input"],
        prediction=result["prediction"],
        confidence=float(result["confidence"]),
        risk_level=result["risk_level"],
        threat_score=int(result["threat_score"]),
        reasons_json=json.dumps(result.get("reasons", [])),
        highlights_json=json.dumps(result.get("highlights", [])),
        intel_json=json.dumps(result.get("threat_intel", {})),
        meta_json=json.dumps(result.get("meta", {})),
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def _scan_to_response(scan: Scan) -> dict:
    meta = json.loads(scan.meta_json or "{}")
    return {
        "ok": True,
        "scan_id": scan.id,
        "created_at": scan.created_at.isoformat() + "Z",
        "prediction": scan.prediction,
        "confidence": scan.confidence,
        "risk_level": scan.risk_level,
        "threat_score": scan.threat_score,
        "reasons": json.loads(scan.reasons_json or "[]"),
        "highlights": json.loads(scan.highlights_json or "[]"),
        "threat_intel": json.loads(scan.intel_json or "{}"),
        "score_breakdown": meta.get("score_breakdown"),
        "meta": meta,
    }


@api_bp.post("/scan")
def scan_api():
    payload = request.get_json(silent=True) or {}
    raw = (payload.get("input") or "").strip()
    input_type_hint = (payload.get("input_type") or "auto").strip().lower()
    heavy = bool(payload.get("heavy", False))

    norm = normalize_and_classify_input(raw, input_type_hint=input_type_hint)
    if not norm["ok"]:
        return jsonify({"ok": False, "error": norm["error"]}), 400

    if heavy:
        job_id = submit_job(
            scan_input,
            raw_input=norm["normalized_input"],
            input_type=norm["input_type"],
            heavy=True,
        )
        return jsonify({"ok": True, "async": True, "job_id": job_id})

    result = scan_input(
        raw_input=norm["normalized_input"],
        input_type=norm["input_type"],
        heavy=False,
    )
    scan = _persist_scan(norm, result)

    return jsonify({"ok": True, "scan_id": scan.id, "created_at": scan.created_at.isoformat() + "Z", **result})


@api_bp.get("/job/<job_id>")
def job_api(job_id: str):
    j = get_job(job_id)
    if not j:
        return jsonify({"ok": False, "error": "Job not found (expired or invalid)."}), 404

    if j["status"] != "done":
        return jsonify({"ok": True, "job_id": job_id, "status": j["status"], "error": j.get("error")})

    # If we've already persisted this job, return the stored scan.
    if j.get("scan_id"):
        scan = Scan.query.get(int(j["scan_id"]))
        if scan:
            return jsonify(_scan_to_response(scan))

    # Persist completed job result as a scan (first retrieval)
    payload = request.args or {}
    raw = (payload.get("input") or "").strip()
    input_type_hint = (payload.get("input_type") or "auto").strip().lower()
    norm = normalize_and_classify_input(raw, input_type_hint=input_type_hint)
    if not norm["ok"]:
        return jsonify({"ok": False, "error": norm["error"]}), 400

    result = j["result"]
    scan = _persist_scan(norm, result)
    attach_scan_id(job_id, scan.id)
    return jsonify({"ok": True, "scan_id": scan.id, "created_at": scan.created_at.isoformat() + "Z", **result})


@api_bp.get("/history")
def history_api():
    query = (request.args.get("query") or "").strip()
    risk = (request.args.get("risk") or "").strip().lower()
    prediction = (request.args.get("prediction") or "").strip().lower()
    limit = min(int(request.args.get("limit") or 50), 200)
    offset = max(int(request.args.get("offset") or 0), 0)

    q = Scan.query
    if query:
        q = q.filter(Scan.raw_input.ilike(f"%{query}%"))
    if risk in {"low", "medium", "high"}:
        q = q.filter(Scan.risk_level == risk)
    if prediction in {"safe", "phishing"}:
        q = q.filter(Scan.prediction == prediction)

    total = q.count()
    rows = q.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()

    items = []
    for s in rows:
        items.append(
            {
                "id": s.id,
                "created_at": s.created_at.isoformat() + "Z",
                "input_type": s.input_type,
                "raw_input": s.raw_input,
                "prediction": s.prediction,
                "confidence": s.confidence,
                "risk_level": s.risk_level,
                "threat_score": s.threat_score,
            }
        )

    return jsonify({"ok": True, "total": total, "limit": limit, "offset": offset, "items": items})


@api_bp.get("/export/<int:scan_id>")
def export_api(scan_id: int):
    fmt = (request.args.get("format") or "json").strip().lower()
    scan = Scan.query.get_or_404(scan_id)

    if fmt == "json":
        meta = json.loads(scan.meta_json or "{}")
        payload = {
            "id": scan.id,
            "created_at": scan.created_at.isoformat() + "Z",
            "input_type": scan.input_type,
            "raw_input": scan.raw_input,
            "prediction": scan.prediction,
            "confidence": scan.confidence,
            "risk_level": scan.risk_level,
            "threat_score": scan.threat_score,
            "reasons": json.loads(scan.reasons_json or "[]"),
            "highlights": json.loads(scan.highlights_json or "[]"),
            "threat_intel": json.loads(scan.intel_json or "{}"),
            "score_breakdown": meta.get("score_breakdown"),
            "meta": meta,
        }
        return jsonify({"ok": True, "exported_at": datetime.utcnow().isoformat() + "Z", "scan": payload})

    if fmt == "pdf":
        pdf_path = export_scan_pdf(scan)
        return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=f"scan_{scan.id}.pdf")

    return jsonify({"ok": False, "error": "Unsupported export format. Use json or pdf."}), 400


@api_bp.post("/chat")
def chat_api():
    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()

    # Accept either scan_id (preferred) or a direct scan_result object
    scan_id = payload.get("scan_id")
    scan_result = payload.get("scan_result")

    if scan_id is not None:
        try:
            scan_id_int = int(scan_id)
        except Exception:
            return jsonify({"ok": False, "error": "scan_id must be an integer."}), 400
        scan = Scan.query.get_or_404(scan_id_int)
        scan_result = _scan_to_response(scan)

    if not isinstance(scan_result, dict):
        return jsonify({"ok": False, "error": "Provide scan_id or scan_result."}), 400

    res = explain_scan_naturally(scan_result, user_message=message)
    return jsonify(res)

