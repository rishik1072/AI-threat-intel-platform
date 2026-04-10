# AI Threat Intelligence & Phishing Detection Platform

Modern phishing detection platform (URL / email text / domain) with:
- Ensemble AI (Random Forest + TF-IDF NLP)
- Explainable AI (reasons, highlights, feature importance)
- Real-time threat intelligence (mockable)
- Advanced URL analysis (homograph, typosquatting, suspicious subdomains)
- SQLite scan history + analytics dashboard (Chart.js)
- REST API (`/api/scan`, `/api/history`, exports)
- Modern glassmorphism UI (dark theme + neon accents, animations, dark/light toggle)

## Quick start

```bash
cd "/media/reven-8827/System Files/MY PROJECTS/ai_threat_intel_platform"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open:
- `http://127.0.0.1:5000/`

## Project structure

- `app.py` - Flask app entrypoint (web UI + API registration)
- `api/` - REST API routes and schemas
- `model/` - ML models + ensemble + training/loading
- `utils/` - feature extraction, explainability helpers, validation, threat intel
- `database/` - SQLite models and DB helpers
- `templates/` - UI pages (Scan, History, Analytics)
- `static/` - CSS/JS assets (glassmorphism, charts, interactions)

## API (high-level)

- `POST /api/scan`
  - Input: `{ "input": "...", "input_type": "auto|url|email|domain", "heavy": false }`
- `GET /api/history?query=&risk=&prediction=&limit=50&offset=0`
- `GET /api/export/<scan_id>?format=json|pdf`

## Notes

- Threat intel supports real providers when configured:
  - **VirusTotal**: set `VT_API_KEY`
  - **Google Safe Browsing**: set `GSB_API_KEY`
  - If keys are missing, the platform falls back to deterministic mock intel so it remains runnable offline.

- NLP model:
  - Default: **TF‑IDF + Logistic Regression** (fast, lightweight)
  - Optional upgrade: **DistilBERT embeddings + Logistic Regression**
    - Install deps: `torch`, `transformers`
    - Enable: `ENABLE_DISTILBERT=1`

