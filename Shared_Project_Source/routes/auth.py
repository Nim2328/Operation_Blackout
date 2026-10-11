from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from services.auth_service import (
    create_user,
    authenticate_user
)


auth_bp = Blueprint(
    "auth",
    __name__
)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user = authenticate_user(
            username,
            password
        )

        if user:

            session.clear()

            session["user_id"] = user.id
            session["username"] = user.username

            return redirect(
                url_for("dashboard.dashboard")
            )

        error = "Invalid investigator credentials."

    return render_template(
        "login.html",
        error=error
    )


@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    error = None

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        team_name = request.form.get("team_name", "")

        try:

            user = create_user(
                username,
                password,
                team_name
            )

            session.clear()

            session["user_id"] = user.id
            session["username"] = user.username

            return redirect(
                url_for("dashboard.dashboard")
            )

        except ValueError as exc:

            error = str(exc)

    return render_template(
        "register.html",
        error=error
    )


@auth_bp.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("auth.login")
    )
