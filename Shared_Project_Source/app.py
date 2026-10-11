from pathlib import Path

from flask import Flask, render_template

from database.models import db


BASE_DIR = Path(__file__).resolve().parent


def create_app():

    app = Flask(__name__)

    # --------------------------------------------------
    # Flask configuration
    # --------------------------------------------------

    app.config["SECRET_KEY"] = "operation-blackout-development-key"

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///"
        + str(BASE_DIR / "instance" / "blackout.db")
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --------------------------------------------------
    # Database
    # --------------------------------------------------

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # --------------------------------------------------
    # Blueprints
    # --------------------------------------------------

    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.stages import stages_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(stages_bp)

    # --------------------------------------------------
    # Main briefing page
    # --------------------------------------------------

    @app.route("/")
    def briefing():
        return render_template("briefing.html")

    # --------------------------------------------------
    # Health check
    # --------------------------------------------------

    @app.route("/health")
    def health():
        return {
            "status": "online",
            "application": "Operation Blackout"
        }

    return app


# ------------------------------------------------------
# Application instance
# ------------------------------------------------------

app = create_app()


# ------------------------------------------------------
# Development server
# ------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=False
    )
