from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for
,
    request
,
    flash
)

from database.models import User, Stage, Progress
from services.progression_service import (
    get_user_score,
    get_completed_stage_count
)


dashboard_bp = Blueprint(
    "dashboard",
    __name__
)


@dashboard_bp.route("/dashboard")
def dashboard():

    user_id = session.get("user_id")

    if not user_id:
        return redirect(
            url_for("auth.login")
        )

    user = User.query.get(user_id)

    if not user:
        session.clear()

        return redirect(
            url_for("auth.login")
        )

    progress_records = (
        Progress.query
        .filter_by(user_id=user.id)
        .join(Stage)
        .order_by(Stage.stage_number)
        .all()
    )

    completed_count = get_completed_stage_count(user)

    score = get_user_score(user)

    return render_template(
        "dashboard.html",
        user=user,
        progress_records=progress_records,
        completed_count=completed_count,
        score=score
    )



@dashboard_bp.route("/reset-progress", methods=["POST"])
def reset_progress():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.form.get("confirm_reset") != "RESET":
        flash("Reset not confirmed. Progress was not changed.", "error")
        return redirect(url_for("dashboard.dashboard"))

    try:
        reset_user_progress(user)
        flash("Your investigation progress has been reset.", "success")
    except Exception:
        from database.models import db
        db.session.rollback()
        flash("Reset failed. No success was reported.", "error")

    return redirect(url_for("dashboard.dashboard"))
