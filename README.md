# AI Threat Intelligence & Phishing Detection Platform

Modern phishing detection platform with ensemble AI, explainability, threat intelligence, real-time UX, and analyst-focused workflow.

## Highlights

- Detects phishing from **URL**, **domain**, and **email text**
- Outputs:
  - Prediction: `phishing | safe`
  - Confidence score
  - Risk level: `low | medium | high`
  - Threat score: `0..100`
- Ensemble detection:
  - Random Forest for structural URL/domain signals
  - NLP classifier (TF-IDF by default, optional DistilBERT embedding backend)
- Explainable AI:
  - Top reasons
  - Suspicious text highlights
  - URL feature importance hints
  - Visual threat score factor breakdown
- Real-time threat intel integration:
  - VirusTotal
  - Google Safe Browsing
  - Cached responses with graceful fallback to mock intel if keys are missing
- Modern glassmorphism dashboard:
  - Scan, History, Analytics pages
  - Dark/Light theme toggle
  - Real-time debounced live scan
  - Subtle particle + micro-interaction polish
- Built-in analyst assistant chatbot for natural-language explanations

## Tech Stack

- **Backend**: Flask, SQLAlchemy, Flask-Limiter
- **ML**: scikit-learn (RF + LR), optional `transformers` + `torch`
- **DB**: SQLite
- **Frontend**: HTML/CSS/JS + Chart.js
- **Exports**: JSON and PDF report

## Project Structure

- `app.py` - app entrypoint + app factory + DB init
- `api/` - REST routes (`/scan`, `/job`, `/history`, `/export`, `/chat`)
- `model/` - training bundle, ensemble logic, explainability, optional DistilBERT embeddings
- `utils/` - scanner orchestration, threat intel providers, validation, async jobs, chatbot
- `database/` - SQLAlchemy models and DB object
- `templates/` - Jinja pages
- `static/` - CSS/JS assets

## Setup

```bash
cd "/media/reven-8827/System Files/MY PROJECTS/ai_threat_intel_platform"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open: [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Environment Variables

### Core

- `HOST` (default `127.0.0.1`)
- `PORT` (default `5000`)
- `FLASK_DEBUG` (default `1`)
- `DATABASE_URL` (default `sqlite:///scans.db`)

### Threat Intelligence

- `VT_API_KEY` - VirusTotal API key
- `GSB_API_KEY` - Google Safe Browsing API key

If not provided, the system falls back to deterministic mock intel.

### NLP Backend

- `ENABLE_DISTILBERT=1` to enable DistilBERT embedding classifier
- `DISTILBERT_MODEL_NAME` (default `distilbert-base-uncased`)

If DistilBERT dependencies/model are unavailable, it automatically falls back to TF-IDF NLP.

## API Reference

### `POST /api/scan`

Request:

```json
{
  "input": "http://example.com/login",
  "input_type": "auto",
  "heavy": false
}
```

Response includes:
- `prediction`, `confidence`, `risk_level`, `threat_score`
- `reasons`, `highlights`
- `threat_intel`
- `score_breakdown`

### `GET /api/job/<job_id>`

Check async deep-scan job status and fetch completed result.

### `GET /api/history`

Filters:
- `query`
- `risk`
- `prediction`
- `limit`, `offset`

### `GET /api/export/<scan_id>?format=json|pdf`

Exports scan result.

### `POST /api/chat`

Natural-language explanation assistant using scan result reasoning:

```json
{
  "scan_id": 123,
  "message": "Why is this phishing?"
}
```

## Screenshots

> Screenshot mapping used:
> - Image 1: Scan page
> - Image 2: History page
> - Image 3: Analytics page
> - Image 4: Chat assistant

![Scan Page](screenshots/scan-page.png)
![History Page](screenshots/history-page.png)
![Analytics Page](screenshots/analytics-page.png)
![Chat Assistant](screenshots/chat-assistant.png)

## Test & Verification

Recommended checks:

```bash
python3 -m py_compile app.py api/routes.py utils/*.py model/*.py database/*.py
node -c static/app.js
```

Manual smoke test:
- Scan URL/domain/email
- Confirm live typing scan updates
- Confirm threat intel provider panel
- Confirm chatbot reply
- Confirm history + analytics + export

## Security Notes

- Input validation and type normalization are enforced server-side.
- Basic rate limiting is enabled.
- Logging enabled via rotating file logs in `logs/app.log`.
- For production, set a strong `SECRET_KEY`, disable debug, and front with a reverse proxy.

