import os
import re
import sqlite3
from pathlib import Path
from io import BytesIO
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from azure.core.exceptions import AzureError, ResourceNotFoundError

from database import get_db_connection, create_tables
from azure_service import AzureBlobService, AzureConfigurationError


# Load variables from the .env file beside this app.py file.
load_dotenv(Path(__file__).with_name(".env"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")

# Limit each upload to 100 MB. Adjust if your project needs larger files.
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

create_tables()

# Create Azure service only when an API request needs it.
_blob_service = None


def get_blob_service():
    global _blob_service
    if _blob_service is None:
        _blob_service = AzureBlobService()
    return _blob_service


def login_required_api(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(success=False, message="Please log in again."), 401
        return view(*args, **kwargs)
    return wrapped


def api_error(message, status=400):
    return jsonify(success=False, message=message), status


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
        confirm_password = request.form.get("confirm_password", "")

        if not name:
            return render_template("signup.html", message="Please enter your full name.")

        email_pattern = r"^[\w.+-]+@[\w-]+\.[\w.-]+$"
        if not re.match(email_pattern, email):
            return render_template("signup.html", message="Please enter a valid email address.")

        if len(password) < 8:
            return render_template("signup.html", message="Password must contain at least 8 characters.")

        if password != confirm_password:
            return render_template("signup.html", message="Passwords do not match.")

        connection = get_db_connection()
        try:
            existing_user = connection.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()

            if existing_user:
                return render_template(
                    "signup.html",
                    message="An account with this email already exists."
                )

            password_hash = generate_password_hash(password)
            connection.execute(
                """
                INSERT INTO users (name, email, password_hash)
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
            return render_template("signup.html", message="Database error. Please try again.")
        finally:
            connection.close()

    return render_template("signup.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
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

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("dashboard"))

        return render_template("login.html", message="Invalid email or password.")

    return render_template("login.html")


# ---------------- PROTECTED DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("index.html", user_name=session.get("user_name"))


# ---------------- AZURE API: LIST FILES ----------------

@app.route("/api/files", methods=["GET"])
@login_required_api
def api_list_files():
    try:
        files = get_blob_service().list_user_files(session["user_id"])
        return jsonify(success=True, files=files)
    except AzureConfigurationError as exc:
        app.logger.error("Azure configuration error: %s", exc)
        return api_error("Azure storage is not configured. Check your .env settings.", 503)
    except AzureError:
        app.logger.exception("Azure error while listing files")
        return api_error("Azure could not list your files. Check the Flask terminal for details.", 502)
    except Exception:
        app.logger.exception("Unexpected error while listing files")
        return api_error("Could not load files. Check the Flask terminal for details.", 500)


# ---------------- AZURE API: UPLOAD ----------------

@app.route("/api/upload", methods=["POST"])
@login_required_api
def api_upload_file():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return api_error("Choose a file to upload.")

    filename = secure_filename(uploaded.filename)
    if not filename:
        return api_error("That filename is not valid.")

    content_type = uploaded.mimetype or "application/octet-stream"

    try:
        get_blob_service().upload_file(
            session["user_id"],
            filename,
            uploaded.stream,
            content_type
        )
        return jsonify(success=True, message=f"{filename} uploaded successfully.")
    except AzureConfigurationError as exc:
        app.logger.error("Azure configuration error: %s", exc)
        return api_error("Azure storage is not configured. Check your .env settings.", 503)
    except AzureError:
        app.logger.exception("Azure error during upload")
        return api_error("Azure upload failed. Check the Flask terminal for details.", 502)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception:
        app.logger.exception("Unexpected upload error")
        return api_error("Upload failed. Check the Flask terminal for details.", 500)


# ---------------- AZURE API: LIST VERSIONS ----------------

@app.route("/api/versions", methods=["GET"])
@login_required_api
def api_list_versions():
    filename = request.args.get("filename", "").strip()
    if not filename:
        return api_error("A filename is required.")

    try:
        versions = get_blob_service().list_versions(session["user_id"], filename)
        return jsonify(success=True, versions=versions)
    except ValueError as exc:
        return api_error(str(exc), 404)
    except AzureConfigurationError as exc:
        app.logger.error("Azure configuration error: %s", exc)
        return api_error("Azure storage is not configured.", 503)
    except AzureError:
        app.logger.exception("Azure error while listing versions")
        return api_error("Could not retrieve versions from Azure.", 502)
    except Exception:
        app.logger.exception("Unexpected version history error")
        return api_error("Could not load version history. Check the Flask terminal.", 500)


# ---------------- AZURE API: RESTORE VERSION ----------------

@app.route("/api/restore", methods=["POST"])
@login_required_api
def api_restore_version():
    payload = request.get_json(silent=True) or {}
    filename = str(payload.get("filename", "")).strip()
    version_id = str(payload.get("version_id", "")).strip()

    if not filename or not version_id:
        return api_error("Filename and version ID are required.")

    try:
        get_blob_service().restore_version(
            session["user_id"], filename, version_id
        )
        return jsonify(success=True, message=f"Restored the selected version of {filename}.")
    except ValueError as exc:
        return api_error(str(exc), 404)
    except AzureConfigurationError as exc:
        app.logger.error("Azure configuration error: %s", exc)
        return api_error("Azure storage is not configured.", 503)
    except AzureError:
        app.logger.exception("Azure error during version restore")
        return api_error("Azure could not restore that version.", 502)
    except Exception:
        app.logger.exception("Unexpected restore error")
        return api_error("Restore failed. Check the Flask terminal.", 500)


# ---------------- AZURE API: DOWNLOAD ----------------

@app.route("/api/download", methods=["GET"])
@login_required_api
def api_download_file():
    filename = request.args.get("filename", "").strip()
    if not filename:
        return api_error("A filename is required.")

    try:
        data, content_type, download_name = get_blob_service().download_file(
            session["user_id"], filename
        )
        return send_file(
            BytesIO(data),
            mimetype=content_type,
            as_attachment=True,
            download_name=download_name
        )
    except ValueError as exc:
        return api_error(str(exc), 404)
    except ResourceNotFoundError:
        return api_error("File not found in Azure.", 404)
    except AzureConfigurationError as exc:
        app.logger.error("Azure configuration error: %s", exc)
        return api_error("Azure storage is not configured.", 503)
    except AzureError:
        app.logger.exception("Azure error during download")
        return api_error("Azure download failed.", 502)
    except Exception:
        app.logger.exception("Unexpected download error")
        return api_error("Download failed. Check the Flask terminal.", 500)


# ---------------- AZURE API: DELETE ----------------

@app.route("/api/delete", methods=["POST"])
@login_required_api
def api_delete_file():
    payload = request.get_json(silent=True) or {}
    filename = str(payload.get("filename", "")).strip()

    if not filename:
        return api_error("A filename is required.")

    try:
        get_blob_service().delete_file(session["user_id"], filename)
        return jsonify(
            success=True,
            message=f"{filename} deleted. Azure soft-delete retention depends on your storage settings."
        )
    except ValueError as exc:
        return api_error(str(exc), 404)
    except AzureConfigurationError as exc:
        app.logger.error("Azure configuration error: %s", exc)
        return api_error("Azure storage is not configured.", 503)
    except AzureError:
        app.logger.exception("Azure error during delete")
        return api_error("Azure could not delete the file.", 502)
    except Exception:
        app.logger.exception("Unexpected delete error")
        return api_error("Delete failed. Check the Flask terminal.", 500)


# ---------------- ERROR HANDLERS ----------------

@app.errorhandler(413)
def file_too_large(_error):
    return jsonify(success=False, message="File is too large. The maximum upload size is 100 MB."), 413


@app.errorhandler(404)
def page_not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify(success=False, message="API endpoint not found."), 404
    return "Page not found", 404


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)
