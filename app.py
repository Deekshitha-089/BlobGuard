
from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)
import re
import sqlite3
import os

from database import get_db_connection, create_tables
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)

# Development secret.
# Set a strong SECRET_KEY environment variable before deployment.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-this-secret"
)

# Create database table if it doesn't exist
create_tables()


# ---------------- LANDING PAGE ----------------

@app.route("/")
def landing():
    return render_template("landing.html")


# ---------------- SIGNUP ----------------

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not name:
            return render_template(
                "signup.html",
                message="Please enter your full name."
            )

        email_pattern = r"^[\w.+-]+@[\w-]+\.[\w.-]+$"

        if not re.match(email_pattern, email):
            return render_template(
                "signup.html",
                message="Please enter a valid email address."
            )

        if len(password) < 8:
            return render_template(
                "signup.html",
                message="Password must contain at least 8 characters."
            )

        if password != confirm_password:
            return render_template(
                "signup.html",
                message="Passwords do not match."
            )

        connection = get_db_connection()

        try:
            existing_user = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing_user:
                return render_template(
                    "signup.html",
                    message="An account with this email already exists."
                )

            password_hash = generate_password_hash(password)

            connection.execute(
                """
                INSERT INTO users
                (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (name, email, password_hash)
            )

            connection.commit()

            return render_template(
                "signup.html",
                message="Account created successfully! You can now log in."
            )

        except sqlite3.Error:
            connection.rollback()

            return render_template(
                "signup.html",
                message="Database error. Please try again."
            )

        finally:
            connection.close()

    return render_template("signup.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        connection = get_db_connection()

        try:
            user = connection.execute(
                """
                SELECT id, name, email, password_hash
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

        finally:
            connection.close()

        # Check whether user exists and password is correct
        if user and check_password_hash(
            user["password_hash"], password
        ):

            # Clear any old session data
            session.clear()

            # Store user ID in the session
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            message="Invalid email or password."
        )

    return render_template("login.html")


# ---------------- PROTECTED DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        user_name=session.get("user_name")
    )


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    # Remove login information from the session
    session.clear()

    return redirect(url_for("landing"))


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)