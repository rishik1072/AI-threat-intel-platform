import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

from flask import Flask, render_template
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database.db import db
from api.routes import api_bp


def create_app() -> Flask:
    load_dotenv()

    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # Logging
    os.makedirs("logs", exist_ok=True)
    handler = RotatingFileHandler("logs/app.log", maxBytes=2_000_000, backupCount=3)
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(handler)

    # SQLite by default (file in project root)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///scans.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Rate limiting (basic; tuned later)
    Limiter(
        get_remote_address,
        app=app,
        default_limits=[
            os.getenv("RATE_LIMIT_DEFAULT", "120 per minute"),
        ],
        storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    )

    db.init_app(app)

    with app.app_context():
        from database.models import Scan  # noqa: F401

        db.create_all()

    # Warm up model artifacts so first scan is fast.
    try:
        from model.bundle import load_or_train

        load_or_train()
        app.logger.info("Model bundle ready.")
    except Exception as e:
        app.logger.warning("Model warm-up failed: %s", e)

    app.register_blueprint(api_bp, url_prefix="/api")

    @app.get("/")
    def scan_page():
        return render_template("scan.html", now=datetime.utcnow())

    @app.get("/history")
    def history_page():
        return render_template("history.html", now=datetime.utcnow())

    @app.get("/analytics")
    def analytics_page():
        return render_template("analytics.html", now=datetime.utcnow())

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1",
    )
