from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(256),
        nullable=False
    )

    team_name = db.Column(
        db.String(100),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    progress = db.relationship(
        "Progress",
        back_populates="user",
        cascade="all, delete-orphan"
    )

class Stage(db.Model):
    __tablename__ = "stages"

    id = db.Column(db.Integer, primary_key=True)
    stage_number = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    domain = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    points = db.Column(db.Integer, nullable=False, default=100)
    flag_hash = db.Column(db.String(64), nullable=False)

    progress = db.relationship(
        "Progress",
        back_populates="stage",
        cascade="all, delete-orphan"
    )


class Progress(db.Model):
    __tablename__ = "progress"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    stage_id = db.Column(
        db.Integer,
        db.ForeignKey("stages.id"),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="locked"
    )

    attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    score_awarded = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    completed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    user = db.relationship(
        "User",
        back_populates="progress"
    )

    stage = db.relationship(
        "Stage",
        back_populates="progress"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "user_id",
            "stage_id",
            name="unique_user_stage"
        ),
    )
