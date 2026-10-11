from werkzeug.security import generate_password_hash, check_password_hash

from database.models import db, User
from services.progression_service import initialize_user_progress


def create_user(username, password, team_name):
    """
    Create a new investigator account with a secure password hash.
    """

    username = username.strip()
    team_name = team_name.strip()

    if not username or not password or not team_name:
        raise ValueError("All fields are required.")

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:
        raise ValueError("Username already exists.")

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        team_name=team_name
    )

    db.session.add(user)
    db.session.commit()

    # Create Stage 01 -> unlocked
    # Stage 02-08 -> locked
    initialize_user_progress(user)

    return user


def authenticate_user(username, password):
    """
    Verify username and password.
    """

    user = User.query.filter_by(
        username=username.strip()
    ).first()

    if not user:
        return None

    if not check_password_hash(
        user.password_hash,
        password
    ):
        return None

    return user
