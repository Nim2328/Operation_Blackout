from database.models import db, Stage, Progress


def initialize_user_progress(user):
    """
    Create one progress record for every stage.

    Stage 01 starts unlocked.
    All later stages remain locked.
    """

    stages = Stage.query.order_by(Stage.stage_number).all()

    for stage in stages:

        existing = Progress.query.filter_by(
            user_id=user.id,
            stage_id=stage.id
        ).first()

        if existing:
            continue

        status = "unlocked" if stage.stage_number == 1 else "locked"

        progress = Progress(
            user_id=user.id,
            stage_id=stage.id,
            status=status,
            attempts=0,
            score_awarded=0
        )

        db.session.add(progress)

    db.session.commit()


def get_user_score(user):
    """
    Return total points earned by the user.
    """

    progress_records = Progress.query.filter_by(
        user_id=user.id,
        status="completed"
    ).all()

    return sum(
        progress.score_awarded
        for progress in progress_records
    )


def get_completed_stage_count(user):
    """
    Return number of completed stages.
    """

    return Progress.query.filter_by(
        user_id=user.id,
        status="completed"
    ).count()


def reset_user_progress(user):
    """
    Reset only the specified user's progress.
    Stage 01 becomes unlocked; all later stages become locked.
    """
    stages = Stage.query.order_by(Stage.stage_number).all()

    for stage in stages:
        progress = Progress.query.filter_by(
            user_id=user.id,
            stage_id=stage.id
        ).first()

        if progress is None:
            progress = Progress(
                user_id=user.id,
                stage_id=stage.id,
                status="locked",
                attempts=0,
                score_awarded=0,
            )
            db.session.add(progress)

        progress.status = (
            "unlocked" if stage.stage_number == 1 else "locked"
        )
        progress.attempts = 0
        progress.score_awarded = 0
        progress.completed_at = None

    db.session.commit()
