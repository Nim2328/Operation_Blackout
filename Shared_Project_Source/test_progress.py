from app import create_app
from database.models import db, User, Stage, Progress
from services.auth_service import create_user
from services.progression_service import initialize_user_progress

app = create_app()

with app.app_context():
    username = "TEAM-07"

    user = User.query.filter_by(username=username).first()

    if not user:
        # Use the application's existing secure account-creation function.
        user = create_user(
            username=username,
            password="Temporary-CTF-Test-Only-2026!",
            team_name="TEAM-07"
        )
        print("Created test investigator:", username)
    else:
        print("Investigator already exists:", username)

    initialize_user_progress(user)

    print()
    print("INVESTIGATION PROGRESS")
    print("======================")

    records = (
        Progress.query
        .filter_by(user_id=user.id)
        .join(Stage)
        .order_by(Stage.stage_number)
        .all()
    )

    for record in records:
        print(
            f"Stage {record.stage.stage_number:02d} | "
            f"{record.stage.name:<22} | "
            f"{record.status:<10} | "
            f"{record.score_awarded} points"
        )
