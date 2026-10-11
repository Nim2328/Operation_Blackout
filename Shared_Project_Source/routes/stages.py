from datetime import datetime
import hashlib

from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    abort,
    request
)

from database.models import db, User, Stage, Progress


stages_bp = Blueprint(
    "stages",
    __name__
)


@stages_bp.route("/stage/<int:stage_number>", methods=["GET", "POST"])
def stage(stage_number):

    # User must be logged in
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

    # Find stage
    stage = Stage.query.filter_by(
        stage_number=stage_number
    ).first()

    if not stage:
        abort(404)

    # Find user's progress
    progress = Progress.query.filter_by(
        user_id=user.id,
        stage_id=stage.id
    ).first()

    if not progress:
        abort(403)

    # Server-side access control
    if progress.status == "locked":
        abort(403)

    message = None
    message_type = None

    # FLAG SUBMISSION
    if request.method == "POST":

        submitted_flag = request.form.get(
            "flag",
            ""
        ).strip()

        # Count every submission attempt
        progress.attempts += 1

        submitted_hash = hashlib.sha256(
            submitted_flag.encode()
        ).hexdigest()

        # Correct flag
        if submitted_hash == stage.flag_hash:

            # Prevent duplicate score awarding
            if progress.status != "completed":

                progress.status = "completed"
                progress.score_awarded = stage.points
                progress.completed_at = datetime.utcnow()

                # Unlock next stage
                next_stage = Stage.query.filter_by(
                    stage_number=stage.stage_number + 1
                ).first()

                if next_stage:

                    next_progress = Progress.query.filter_by(
                        user_id=user.id,
                        stage_id=next_stage.id
                    ).first()

                    if next_progress is None:
                        next_progress = Progress(
                            user_id=user.id,
                            stage_id=next_stage.id,
                            status="unlocked",
                            attempts=0,
                            score_awarded=0,
                        )
                        db.session.add(next_progress)
                    elif next_progress.status == "locked":
                        next_progress.status = "unlocked"

                db.session.commit()

                message = (
                    f"Correct flag. Stage {stage.stage_number:02d} "
                    f"completed. {stage.points} points awarded."
                )

                message_type = "success"

            else:

                db.session.commit()

                message = "Stage already completed."

                message_type = "info"

        # Wrong flag
        else:

            db.session.commit()

            message = "Incorrect flag. Investigate the evidence and try again."

            message_type = "error"

    next_stage = Stage.query.filter_by(
        stage_number=stage.stage_number + 1
    ).first()

    next_progress = None
    if next_stage:
        next_progress = Progress.query.filter_by(
            user_id=user.id,
            stage_id=next_stage.id
        ).first()

    return render_template(
        "stage.html",
        user=user,
        stage=stage,
        progress=progress,
        message=message,
        message_type=message_type,
        next_stage=next_stage,
        next_progress=next_progress
    )
