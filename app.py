from __future__ import annotations

"""Werving App — Flask + SQLite

Dit bestand bevat de Flask routes en helperfuncties.
Database- en service-logica is opgesplitst in:
- db/connection.py
- services/audit_service.py
- services/email_service.py
"""

# ============================================================
# Local project modules (extracted services / db)
# ============================================================
from db.connection import get_database_connection
from services.audit_service import log_audit_event
from services.email_service import send_email, format_datetime_for_email

# ============================================================
# Standard library
# ============================================================
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Sequence, List
from urllib.parse import urlparse

# ============================================================
# Third-party libraries
# ============================================================
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()


# ============================================================
# Roles (internal users)
# ============================================================

ROLE_MANAGER = "manager"
ROLE_RECRUITER = "recruiter"
ROLE_INTERVIEWER = "interviewer"
ROLE_ADMIN = "admin"



# ============================================================
# Vacancy workflow statuses
# ============================================================

JOB_STATUS_DRAFT = "draft"
JOB_STATUS_PENDING_REVIEW = "pending_review"
JOB_STATUS_PUBLISHED = "published"
JOB_STATUS_CHANGES_REQUESTED = "changes_requested"
JOB_STATUS_CLOSED = "closed"

JOB_STATUS_LABELS = {
    JOB_STATUS_DRAFT: "Draft",
    JOB_STATUS_PENDING_REVIEW: "Pending review",
    JOB_STATUS_PUBLISHED: "Published",
    JOB_STATUS_CHANGES_REQUESTED: "Changes requested",
    JOB_STATUS_CLOSED: "Closed",
}

ALLOWED_JOB_STATUSES = {
    JOB_STATUS_DRAFT,
    JOB_STATUS_PENDING_REVIEW,
    JOB_STATUS_PUBLISHED,
    JOB_STATUS_CHANGES_REQUESTED,
    JOB_STATUS_CLOSED,
}



# ============================================================
# Application workflow statuses
# ============================================================

APP_STATUS_NEW = "new"
APP_STATUS_IN_REVIEW = "in_review"
APP_STATUS_SHORTLISTED = "shortlisted"
APP_STATUS_INTERVIEW = "interview"
APP_STATUS_REJECTED = "rejected"
APP_STATUS_OFFERED = "offered"
APP_STATUS_HIRED = "hired"
APP_STATUS_WITHDRAWN = "withdrawn"

APP_STATUS_LABELS = {
    APP_STATUS_NEW: "New",
    APP_STATUS_IN_REVIEW: "In review",
    APP_STATUS_SHORTLISTED: "Shortlisted",
    APP_STATUS_INTERVIEW: "Interview",
    APP_STATUS_REJECTED: "Rejected",
    APP_STATUS_OFFERED: "Offered",
    APP_STATUS_HIRED: "Hired",
    APP_STATUS_WITHDRAWN: "Withdrawn",
}

ALLOWED_APPLICATION_STATUSES = {
    APP_STATUS_NEW,
    APP_STATUS_IN_REVIEW,
    APP_STATUS_SHORTLISTED,
    APP_STATUS_INTERVIEW,
    APP_STATUS_REJECTED,
    APP_STATUS_OFFERED,
    APP_STATUS_HIRED,
    APP_STATUS_WITHDRAWN,
}

FINAL_APPLICATION_STATUSES = {APP_STATUS_WITHDRAWN, APP_STATUS_REJECTED, APP_STATUS_HIRED}

# Kandidaatvriendelijke labels (extern)
PUBLIC_APP_STATUS_LABELS = {
    APP_STATUS_NEW: "Sollicitatie ontvangen",
    APP_STATUS_IN_REVIEW: "In behandeling",
    APP_STATUS_SHORTLISTED: "In behandeling",
    APP_STATUS_INTERVIEW: "Uitgenodigd voor gesprek",
    APP_STATUS_OFFERED: "Aanbod",
    APP_STATUS_HIRED: "Aangenomen",
    APP_STATUS_REJECTED: "Afgewezen",
    APP_STATUS_WITHDRAWN: "Ingetrokken",
}



# ============================================================
# Flask app setup
# ============================================================

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Security / cookie defaults + upload size limit
# In production: set FLASK_SECRET_KEY to a strong random value!
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_SESSION_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024))),  # default 10MB
)


@app.errorhandler(413)
def file_too_large(_err):
    flash("Bestand is te groot. Probeer een kleiner bestand.")
    return redirect(request.referrer or url_for("vacancy_list_page"))



# ============================================================
# Helpers
# ============================================================



def safe_next_url(next_url: str, fallback_endpoint: str = "vacancy_list_page") -> str:
    next_url = (next_url or "").strip()
    if not next_url:
        return url_for(fallback_endpoint)

    # Alleen interne paden toelaten: "/iets", niet "http://..."
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return url_for(fallback_endpoint)

    # vermijd "//evil.com"
    if next_url.startswith("//"):
        return url_for(fallback_endpoint)

    if not next_url.startswith("/"):
        return url_for(fallback_endpoint)

    return next_url

def require_candidate() -> bool:
    return "candidate_id" in session

def create_set_password_token() -> str:
    return secrets.token_urlsafe(32)

def set_password_expiry(hours: int = 24) -> str:
    # SQLite-friendly string
    return (datetime.utcnow() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_safe_choice(value: Optional[str], allowed: Sequence[str], default: str) -> str:
    if not value or value not in allowed:
        return default
    return value

def require_role(required_role: str) -> bool:
    return "user_id" in session and session.get("user_role") == required_role


def require_any_role(allowed_roles: Sequence[str]) -> bool:
    return "user_id" in session and session.get("user_role") in set(allowed_roles)


def is_candidate_logged_in() -> bool:
    return "candidate_id" in session


def create_safe_storage_filename(original_filename: str) -> str:
    original_filename = (original_filename or "").strip()
    extension = original_filename.rsplit(".", 1)[1].lower() if "." in original_filename else ""
    random_part = secrets.token_urlsafe(16)
    return f"{random_part}.{extension}" if extension else random_part


def normalize_datetime_local(input_value: str) -> str:
    """
    Converts HTML datetime-local (YYYY-MM-DDTHH:MM) into SQLite-friendly format.
    Output: YYYY-MM-DD HH:MM:SS
    """
    value = (input_value or "").strip()
    if not value:
        return value
    value = value.replace("T", " ")
    if len(value) == 16:
        value = value + ":00"
    return value

def build_publish_checks(database_connection: sqlite3.Connection, vacancy_id: int) -> Dict[str, Any]:
    """
    Publish is allowed only if:
    - At least 1 active interview phase exists
    - Each active phase has a template_version_id
    - Each template_version is published
    - Each template_version has at least 3 template_aspects
    """
    missing_items: List[str] = []

    phases = database_connection.execute(
        """
        SELECT p.id, p.phase_name, p.sequence_number, p.template_version_id,
               tv.status AS template_status
        FROM interview_phases p
        LEFT JOIN template_versions tv ON tv.id = p.template_version_id
        WHERE p.vacancy_id = ? AND p.is_active = 1
        ORDER BY p.sequence_number ASC
        """,
        (vacancy_id,),
    ).fetchall()

    if not phases:
        missing_items.append("Geen interviewfases ingesteld voor deze vacature.")
        return {"is_ready": False, "missing_items": missing_items}

    for phase in phases:
        if not phase["template_version_id"]:
            missing_items.append(f"Fase '{phase['phase_name']}' heeft geen evaluatietemplate.")
            continue

        if (phase["template_status"] or "") != "published":
            missing_items.append(f"Template voor fase '{phase['phase_name']}' is niet gepubliceerd.")

        aspect_count_row = database_connection.execute(
            "SELECT COUNT(*) AS cnt FROM template_aspects WHERE template_version_id = ?",
            (phase["template_version_id"],),
        ).fetchone()
        if not aspect_count_row or int(aspect_count_row["cnt"]) < 3:
            missing_items.append(
                f"Template voor fase '{phase['phase_name']}' heeft minder dan 3 criteria/aspects."
            )

    return {"is_ready": len(missing_items) == 0, "missing_items": missing_items}


def get_first_active_phase_id(database_connection: sqlite3.Connection, vacancy_id: int) -> Optional[int]:
    row = database_connection.execute(
        """
        SELECT id
        FROM interview_phases
        WHERE vacancy_id = ? AND is_active = 1
        ORDER BY sequence_number ASC
        LIMIT 1
        """,
        (vacancy_id,),
    ).fetchone()
    return int(row["id"]) if row else None


def is_user_assigned_to_interview(database_connection: sqlite3.Connection, interview_id: int, user_id: int) -> bool:
    row = database_connection.execute(
        """
        SELECT 1
        FROM interview_interviewers
        WHERE interview_id = ? AND interviewer_user_id = ?
        LIMIT 1
        """,
        (interview_id, user_id),
    ).fetchone()
    return row is not None


def get_assigned_interviewers_for_phase(database_connection: sqlite3.Connection, phase_id: int) -> List[sqlite3.Row]:
    """
    Returns users assigned by manager to a phase (phase_interviewers).
    Only active ROLE_INTERVIEWER users.
    """
    return database_connection.execute(
        """
        SELECT u.id, u.email_address, u.full_name
        FROM phase_interviewers pi
        JOIN users u ON u.id = pi.interviewer_user_id
        WHERE pi.phase_id = ? AND u.is_active = 1 AND u.user_role = ?
        ORDER BY COALESCE(u.full_name, u.email_address) ASC
        """,
        (phase_id, ROLE_INTERVIEWER),
    ).fetchall()


def get_phase_interviewer_map_for_vacancy(
    database_connection: sqlite3.Connection,
    vacancy_id: int
) -> Dict[int, List[Dict[str, Any]]]:
    """
    For all ACTIVE phases in a vacancy:
    returns dict phase_id -> list of {id, label}
    (label = "Full Name (email)" of enkel "email" als naam ontbreekt)
    """
    phases = database_connection.execute(
        """
        SELECT id
        FROM interview_phases
        WHERE vacancy_id = ? AND is_active = 1
        """,
        (vacancy_id,),
    ).fetchall()

    mapping: Dict[int, List[Dict[str, Any]]] = {}

    for p in phases:
        pid = int(p["id"])
        assigned = get_assigned_interviewers_for_phase(database_connection, pid)

        mapping[pid] = [
            {
                "id": int(u["id"]),
                "label": (
                    f"{u['full_name']} ({u['email_address']})"
                    if (u["full_name"] or "").strip()
                    else u["email_address"]
                ),
            }
            for u in assigned
        ]

    return mapping



# ============================================================
# 1) Authentication (internal users)
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        input_email = request.form.get("form_email", "").strip().lower()
        input_password = request.form.get("form_password", "")

        if not input_email or not input_password:
            flash("Vul je e-mail en wachtwoord in.")
            return render_template("login.html")

        db = get_database_connection()

        # 1) probeer personeel
        user_row = db.execute(
            "SELECT * FROM users WHERE email_address = ? AND is_active = 1",
            (input_email,),
        ).fetchone()

        if user_row and check_password_hash(user_row["password_hash"], input_password):
            session.clear()
            session["user_id"] = user_row["id"]
            session["user_role"] = user_row["user_role"]
            session["user_email"] = user_row["email_address"]
            db.close()
            return redirect(url_for("dashboard_page"))

        # 2) probeer kandidaat
        candidate_row = db.execute(
            """
            SELECT id, email_address, password_hash
            FROM candidates
            WHERE email_address = ? AND is_active = 1
            """,
            (input_email,),
        ).fetchone()

        db.close()

        if candidate_row and candidate_row["password_hash"] and check_password_hash(candidate_row["password_hash"], input_password):
            session.clear()
            session["candidate_id"] = candidate_row["id"]
            session["candidate_email"] = candidate_row["email_address"]
            return redirect(url_for("candidate_dashboard_page"))

        flash("Ongeldige login.")
        return render_template("login.html")

    return render_template("login.html")

@app.route("/candidate/dashboard")
def candidate_dashboard_page():
    if "candidate_id" not in session:
        return redirect(url_for("login_page"))

    db = get_database_connection()
    row = db.execute(
        """
        SELECT status_view_token
        FROM applications
        WHERE candidate_id = ?
        ORDER BY applied_at DESC, id DESC
        LIMIT 1
        """,
        (session["candidate_id"],),
    ).fetchone()
    db.close()

    if not row:
        flash("Je hebt nog geen sollicitaties.")
        return redirect(url_for("vacancy_list_page"))

    return redirect(url_for("application_status_page", token=row["status_view_token"]))

@app.route("/candidate/set-password/<token>", methods=["GET", "POST"])
def candidate_set_password_page(token: str):
    token = (token or "").strip()
    next_url = request.args.get("next", "")

    db = get_database_connection()
    candidate = db.execute(
        """
        SELECT id, email_address, set_password_expires_at
        FROM candidates
        WHERE set_password_token = ? AND is_active = 1
        """,
        (token,),
    ).fetchone()

    if not candidate:
        db.close()
        flash("Ongeldige of verlopen link.")
        return redirect(url_for("vacancy_list_page"))

    # Expiry check (SQLite datetime string: "YYYY-MM-DD HH:MM:SS")
    expires_at_raw = (candidate["set_password_expires_at"] or "").strip()
    if expires_at_raw:
        try:
            expires_at = datetime.strptime(expires_at_raw, "%Y-%m-%d %H:%M:%S")
            if datetime.utcnow() > expires_at:
                db.execute(
                    """
                    UPDATE candidates
                    SET set_password_token = NULL,
                        set_password_expires_at = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (int(candidate["id"]),),
                )
                db.commit()
                db.close()
                flash("Ongeldige of verlopen link.")
                return redirect(url_for("vacancy_list_page"))
        except ValueError:
            # Als parsing faalt: beschouw als ongeldig/verlopen
            db.close()
            flash("Ongeldige of verlopen link.")
            return redirect(url_for("vacancy_list_page"))

    if request.method == "POST":
        pw1 = (request.form.get("password1") or request.form.get("password") or "").strip()
        pw2 = (request.form.get("password2") or request.form.get("password_confirm") or "").strip()

        if not pw1 or len(pw1) < 8:
            db.close()
            flash("Wachtwoord moet minstens 8 karakters zijn.")
            return redirect(url_for("candidate_set_password_page", token=token, next=next_url))

        if pw1 != pw2:
            db.close()
            flash("Wachtwoorden komen niet overeen.")
            return redirect(url_for("candidate_set_password_page", token=token, next=next_url))

        password_hash = generate_password_hash(pw1)

        db.execute(
            """
            UPDATE candidates
            SET password_hash = ?,
                set_password_token = NULL,
                set_password_expires_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (password_hash, int(candidate["id"])),
        )
        db.commit()
        db.close()

        session.clear()
        session["candidate_id"] = int(candidate["id"])
        session["candidate_email"] = candidate["email_address"]

        return redirect(safe_next_url(next_url, fallback_endpoint="candidate_dashboard_page"))

    db.close()
    return render_template("candidate_set_password.html", token=token, next=next_url)

@app.route("/dashboard")
def dashboard_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    user_role = session.get("user_role")
    upcoming_interviews = []

    # Voor interviewers: toon komende interviews op dashboard
    if user_role == ROLE_INTERVIEWER:
        database_connection = get_database_connection()
        upcoming_interviews = database_connection.execute(
            """
            SELECT
                i.id,
                i.scheduled_start AS scheduled_start,
                i.status AS status,
                p.phase_name AS phase_name,
                c.full_name AS candidate_name,
                v.title AS vacancy_title,

                (
                    SELECT e.evaluation_status
                    FROM evaluations e
                    WHERE e.interview_id = i.id
                      AND e.interviewer_user_id = ?
                    ORDER BY e.updated_at DESC, e.id DESC
                    LIMIT 1
                ) AS evaluation_status

            FROM interviews i
            JOIN interview_interviewers ii ON ii.interview_id = i.id
            JOIN applications a ON i.application_id = a.id
            JOIN candidates c ON a.candidate_id = c.id
            JOIN vacancies v ON a.vacancy_id = v.id
            LEFT JOIN interview_phases p ON p.id = i.phase_id
            WHERE ii.interviewer_user_id = ?
            ORDER BY i.scheduled_start ASC
            LIMIT 5
            """,
            (session["user_id"], session["user_id"]),
        ).fetchall()
        database_connection.close()

    return render_template(
        "dashboard.html",
        user_email=session.get("user_email"),
        user_role=user_role,
        upcoming_interviews=upcoming_interviews,
    )



@app.route("/logout")
def logout_action():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login_page"))



# ============================================================
# 2) Public pages
# ============================================================

@app.route("/")
def home():
    return redirect(url_for("vacancy_list_page"))


@app.route("/vacatures")
def vacancy_list_page():
    database_connection = get_database_connection()
    vacancies = database_connection.execute(
        """
        SELECT *
        FROM vacancies
        WHERE status = ?
        ORDER BY published_at DESC, created_at DESC
        """,
        (JOB_STATUS_PUBLISHED,),
    ).fetchall()
    database_connection.close()

    return render_template("vacancies.html", vacancies=vacancies)


@app.route("/solliciteer/<int:vacancy_id>", methods=["GET", "POST"])
def apply_page(vacancy_id: int):
    database_connection = get_database_connection()

    vacancy = database_connection.execute(
        "SELECT * FROM vacancies WHERE id = ?",
        (vacancy_id,),
    ).fetchone()

    if not vacancy or vacancy["status"] != JOB_STATUS_PUBLISHED:
        database_connection.close()
        flash("This job posting is not publicly available.")
        return redirect(url_for("vacancy_list_page"))

    if request.method == "POST":
        candidate_name = request.form.get("candidate_name", "").strip()
        candidate_email = request.form.get("candidate_email", "").strip().lower()
        cover_letter = request.form.get("candidate_motivation", "").strip()
        uploaded_file = request.files.get("candidate_cv")

        gdpr_consent = 1 if (request.form.get("gdpr_consent") == "1") else 0
        if gdpr_consent != 1:
            flash("Gelieve toestemming te geven voor de verwerking van je gegevens (GDPR).")
            database_connection.close()
            return render_template("apply.html", vacancy=vacancy)

        if not candidate_name or not candidate_email:
            flash("Please fill in your name and email address.")
            database_connection.close()
            return render_template("apply.html", vacancy=vacancy)

        if not uploaded_file or uploaded_file.filename.strip() == "":
            flash("Please upload your CV (PDF/DOC/DOCX).")
            database_connection.close()
            return render_template("apply.html", vacancy=vacancy)

        if not allowed_file(uploaded_file.filename):
            flash("Invalid file type. Allowed: PDF, DOC, DOCX.")
            database_connection.close()
            return render_template("apply.html", vacancy=vacancy)

        original_filename = secure_filename(uploaded_file.filename)
        storage_filename = create_safe_storage_filename(original_filename)
        uploaded_file.save(os.path.join(app.config["UPLOAD_FOLDER"], storage_filename))

        # 1) Candidate ophalen/aanmaken -> candidate_id DEFINITIEF bepalen
        existing_candidate = database_connection.execute(
            "SELECT id, full_name, password_hash FROM candidates WHERE email_address = ? AND is_active = 1",
            (candidate_email,),
        ).fetchone()

        if existing_candidate:
            candidate_id = int(existing_candidate["id"])
            if candidate_name and (existing_candidate["full_name"] or "").strip() != candidate_name:
                database_connection.execute(
                    "UPDATE candidates SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (candidate_name, candidate_id),
                )
        else:
            cursor = database_connection.cursor()
            cursor.execute(
                """
                INSERT INTO candidates (email_address, full_name, is_active, created_at)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP)
                """,
                (candidate_email, candidate_name),
            )
            candidate_id = int(cursor.lastrowid)

        # 2) Dubbele sollicitatie check
        existing_application = database_connection.execute(
            """
            SELECT id, status, status_view_token, applied_at
            FROM applications
            WHERE vacancy_id = ? AND candidate_id = ?
            ORDER BY applied_at DESC, id DESC
            LIMIT 1
            """,
            (vacancy_id, candidate_id),
        ).fetchone()

        if existing_application and (existing_application["status"] or "") != APP_STATUS_WITHDRAWN:
            existing_token = existing_application["status_view_token"]
            database_connection.commit()
            database_connection.close()

            flash("Je hebt al gesolliciteerd op deze vacature met dit e-mailadres.")
            return redirect(url_for("application_status_page", token=existing_token))

        # 3) Sollicitatie aanmaken
        status_view_token = secrets.token_urlsafe(24)

        cursor = database_connection.cursor()
        cursor.execute(
            """
            INSERT INTO applications (
                vacancy_id,
                candidate_id,
                status,
                applied_at,
                status_updated_at,
                status_updated_by_candidate_id,
                cover_letter,
                resume_original_filename,
                resume_storage_filename,
                status_view_token,
                gdpr_consent,
                gdpr_consent_at
            )
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                vacancy_id,
                candidate_id,
                APP_STATUS_NEW,
                candidate_id,
                cover_letter if cover_letter else None,
                original_filename,
                storage_filename,
                status_view_token,
                gdpr_consent,
            ),
        )
        application_id = int(cursor.lastrowid)

        log_audit_event(
            database_connection,
            event_type="application_created",
            entity_type="application",
            entity_id=application_id,
            to_status=APP_STATUS_NEW,
            details={"vacancy_id": vacancy_id, "gdpr_consent": True},
            performed_by_candidate_id=candidate_id,
        )

        # 4) Check password_hash (bepaalt of we set-password flow starten)
        row = database_connection.execute(
            "SELECT password_hash FROM candidates WHERE id = ?",
            (candidate_id,),
        ).fetchone()
        password_hash = row["password_hash"] if row else None

        # Maak externe status URL voor mail
        status_url_external = url_for("application_status_page", token=status_view_token, _external=True)

        # Indien nog geen wachtwoord: token aanmaken + opslaan (zelfde DB-transaction)
        set_pw_external = None
        token = None
        if not password_hash:
            token = create_set_password_token()
            expires = set_password_expiry(hours=24)

            database_connection.execute(
                """
                UPDATE candidates
                SET set_password_token = ?,
                    set_password_expires_at = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (token, expires, candidate_id),
            )

            set_pw_external = url_for(
                "candidate_set_password_page",
                token=token,
                next=status_url_external,
                _external=True,
            )

        database_connection.commit()
        database_connection.close()

        # ---------- EMAIL NA SOLLICITATIE ----------
        try:
            subject = f"Bevestiging sollicitatie — {vacancy['title'] if 'title' in vacancy.keys() else 'Vacature'}"

            text_lines = [
                f"Hallo {candidate_name},",
                "",
                "We hebben je sollicitatie goed ontvangen.",
                f"Volg je status hier: {status_url_external}",
            ]
            if set_pw_external:
                text_lines += [
                    "",
                    "Maak je account aan door je wachtwoord in te stellen:",
                    set_pw_external,
                ]

            ok, err = send_email(
                to_email=candidate_email,
                subject=subject,
                text_body="\n".join(text_lines),
                html_body=None,
            )
            if not ok:
                print("EMAIL ERROR (apply):", err)
        except Exception as e:
            print("EMAIL ERROR (apply unexpected):", e)
        # -----------------------------------------

        # Redirects
        if not password_hash and token:
            # redirect naar set-password met next naar status (intern pad ok)
            status_url_internal = url_for("application_status_page", token=status_view_token)
            return redirect(url_for("candidate_set_password_page", token=token, next=status_url_internal))

        # kandidaat heeft al password => auto-login en naar status
        session.clear()
        session["candidate_id"] = candidate_id
        session["candidate_email"] = candidate_email
        return redirect(url_for("application_status_page", token=status_view_token))

    database_connection.close()
    return render_template("apply.html", vacancy=vacancy)


@app.route("/application-status/<token>", methods=["GET", "POST"])
def application_status_page(token: str):
    token = (token or "").strip()
    if not token:
        return redirect(url_for("vacancy_list_page"))

    database_connection = get_database_connection()
    application = database_connection.execute(
        """
        SELECT
            a.id,
            a.status,
            a.applied_at,
            a.withdrawn_at,
            a.withdrawn_reason,
            v.title AS vacancy_title,
            c.full_name AS candidate_name,
            c.email_address AS candidate_email
        FROM applications a
        JOIN vacancies v ON a.vacancy_id = v.id
        JOIN candidates c ON a.candidate_id = c.id
        WHERE a.status_view_token = ?
        """,
        (token,),
    ).fetchone()

    if not application:
        database_connection.close()
        flash("Invalid tracking link.")
        return redirect(url_for("vacancy_list_page"))

    # ✅ NEW: eerstvolgende geplande interview (met meeting_link = Teams link)
    upcoming_interview = database_connection.execute(
        """
        SELECT
            i.scheduled_start,
            i.location,
            i.meeting_link,
            p.phase_name
        FROM interviews i
        LEFT JOIN interview_phases p ON p.id = i.phase_id
        WHERE i.application_id = ?
          AND i.status = 'planned'
        ORDER BY i.scheduled_start ASC
        LIMIT 1
        """,
        (application["id"],),
    ).fetchone()

    if request.method == "POST":
        current_status = application["status"]
        if current_status in FINAL_APPLICATION_STATUSES:
            database_connection.close()
            flash("This application can no longer be withdrawn.")
            return redirect(url_for("application_status_page", token=token))

        withdraw_reason = request.form.get("withdraw_reason", "").strip()

        database_connection.execute(
            """
            UPDATE applications
            SET status = ?,
                withdrawn_at = CURRENT_TIMESTAMP,
                withdrawn_reason = ?,
                status_updated_at = CURRENT_TIMESTAMP,
                status_updated_by_user_id = NULL,
                status_updated_by_candidate_id = candidate_id
            WHERE status_view_token = ?
            """,
            (APP_STATUS_WITHDRAWN, withdraw_reason if withdraw_reason else None, token),
        )

        candidate_id = database_connection.execute(
            "SELECT candidate_id FROM applications WHERE status_view_token = ?",
            (token,),
        ).fetchone()["candidate_id"]

        log_audit_event(
            database_connection,
            event_type="application_withdrawn",
            entity_type="application",
            entity_id=application["id"],
            from_status=current_status,
            to_status=APP_STATUS_WITHDRAWN,
            details={"reason": withdraw_reason} if withdraw_reason else {},
            performed_by_candidate_id=candidate_id,
        )

        database_connection.commit()
        database_connection.close()

        flash("Your application has been withdrawn.")
        return redirect(url_for("application_status_page", token=token))

    database_connection.close()
    return render_template(
        "application_status.html",
        application=application,
        status_labels=PUBLIC_APP_STATUS_LABELS,
        upcoming_interview=upcoming_interview,  # ✅ dit activeert je template-blok
    )




# ============================================================
# 3) File download (CV)
# ============================================================

@app.route("/uploads/<filename>")
def download_file(filename: str):
    filename = secure_filename((filename or "").strip())
    if not filename:
        return redirect(url_for("vacancy_list_page"))

    database_connection = get_database_connection()

    application_row = database_connection.execute(
        """
        SELECT
            a.id AS application_id,
            a.candidate_id,
            v.manager_id
        FROM applications a
        JOIN vacancies v ON a.vacancy_id = v.id
        WHERE a.resume_storage_filename = ?
        """,
        (filename,),
    ).fetchone()

    if not application_row:
        database_connection.close()
        flash("File not found.")
        return redirect(url_for("dashboard_page") if "user_id" in session else url_for("vacancy_list_page"))

    is_allowed = False

    if "user_id" in session:
        user_role = session.get("user_role")
        user_id = session.get("user_id")

        if user_role in {ROLE_RECRUITER, ROLE_ADMIN}:
            is_allowed = True
        elif user_role == ROLE_MANAGER and application_row["manager_id"] == user_id:
            is_allowed = True
        elif user_role == ROLE_INTERVIEWER:
            assigned = database_connection.execute(
                """
                SELECT 1
                FROM interviews i
                JOIN interview_interviewers ii ON ii.interview_id = i.id
                WHERE i.application_id = ? AND ii.interviewer_user_id = ?
                LIMIT 1
                """,
                (application_row["application_id"], user_id),
            ).fetchone()
            is_allowed = assigned is not None

    elif is_candidate_logged_in():
        if session.get("candidate_id") == application_row["candidate_id"]:
            is_allowed = True

    database_connection.close()

    if not is_allowed:
        flash("You do not have access to this file.")
        return redirect(url_for("dashboard_page") if "user_id" in session else url_for("vacancy_list_page"))

    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)



# ============================================================
# 4) Manager: create + manage vacancies
# ============================================================

@app.route("/create-vacancy", methods=["GET", "POST"])
def create_vacancy_page():
    if not require_role(ROLE_MANAGER):
        return redirect(url_for("dashboard_page"))

    if request.method == "POST":
        title = request.form.get("vacancy_title", "").strip()
        department = request.form.get("vacancy_department", "").strip()
        description = request.form.get("vacancy_description", "").strip()

        location = request.form.get("vacancy_location", "").strip() or None
        employment_type = request.form.get("employment_type", "").strip() or None
        experience_level = request.form.get("experience_level", "").strip() or None

        manager_id = session["user_id"]

        if not title or not department or not description:
            flash("Please fill in title, department and description.")
            return render_template("create_vacancy.html")

        database_connection = get_database_connection()
        cursor = database_connection.cursor()
        cursor.execute(
            """
            INSERT INTO vacancies (
                title, department, description,
                location, employment_type, experience_level,
                manager_id, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                title,
                department,
                description,
                location,
                employment_type,
                experience_level,
                manager_id,
                JOB_STATUS_DRAFT,
            ),
        )
        vacancy_id = cursor.lastrowid

        log_audit_event(
            database_connection,
            event_type="vacancy_created",
            entity_type="vacancy",
            entity_id=vacancy_id,
            to_status=JOB_STATUS_DRAFT,
            performed_by_user_id=manager_id,
        )

        database_connection.commit()
        database_connection.close()

        flash("Job posting created as Draft.")
        return redirect(url_for("manager_job_postings_page"))

    return render_template("create_vacancy.html")


@app.route("/manager/job-postings")
def manager_job_postings_page():
    if not require_role(ROLE_MANAGER):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    job_postings = database_connection.execute(
        """
        SELECT *
        FROM vacancies
        WHERE manager_id = ?
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    ).fetchall()
    database_connection.close()

    return render_template("manager_job_postings.html", jobs=job_postings, status_labels=JOB_STATUS_LABELS)


@app.route("/manager/job-postings/<int:job_id>/submit", methods=["POST"])
def submit_job_posting_for_review_action(job_id: int):
    if not require_role(ROLE_MANAGER):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    job = database_connection.execute(
        "SELECT * FROM vacancies WHERE id = ? AND manager_id = ?",
        (job_id, session["user_id"]),
    ).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("manager_job_postings_page"))

    if job["status"] not in {JOB_STATUS_DRAFT, JOB_STATUS_CHANGES_REQUESTED}:
        database_connection.close()
        flash("This job posting cannot be submitted in its current status.")
        return redirect(url_for("manager_job_postings_page"))

    previous_status = job["status"]

    database_connection.execute(
        """
        UPDATE vacancies
        SET status = ?,
            submitted_at = CURRENT_TIMESTAMP,
            review_comment = NULL,
            reviewed_by_user_id = NULL,
            reviewed_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (JOB_STATUS_PENDING_REVIEW, job_id),
    )

    log_audit_event(
        database_connection,
        event_type="vacancy_submitted_for_review",
        entity_type="vacancy",
        entity_id=job_id,
        from_status=previous_status,
        to_status=JOB_STATUS_PENDING_REVIEW,
        performed_by_user_id=session["user_id"],
    )

    database_connection.commit()
    database_connection.close()

    flash("Submitted for review.")
    return redirect(url_for("manager_job_postings_page"))



# ============================================================
# 4B) Manager: assign interviewers per phase (phase 2+)
# ============================================================

@app.route("/manager/job-postings/<int:job_id>/phase-interviewers")
def manager_phase_interviewers_page(job_id: int):
    if not require_role(ROLE_MANAGER):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    job = database_connection.execute(
        "SELECT id, title, manager_id FROM vacancies WHERE id = ?",
        (job_id,),
    ).fetchone()
    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("manager_job_postings_page"))

    if int(job["manager_id"]) != int(session["user_id"]):
        database_connection.close()
        flash("You do not have access to this job posting.")
        return redirect(url_for("manager_job_postings_page"))

    phases = database_connection.execute(
        """
        SELECT id, phase_name, sequence_number, is_active
        FROM interview_phases
        WHERE vacancy_id = ?
        ORDER BY sequence_number ASC
        """,
        (job_id,),
    ).fetchall()

    interviewers = database_connection.execute(
        """
        SELECT id, email_address, full_name
        FROM users
        WHERE user_role = ? AND is_active = 1
        ORDER BY COALESCE(full_name, email_address) ASC
        """,
        (ROLE_INTERVIEWER,),
    ).fetchall()

    assignments_rows = database_connection.execute(
        """
        SELECT pi.phase_id, u.id AS interviewer_id, u.email_address, u.full_name
        FROM phase_interviewers pi
        JOIN users u ON u.id = pi.interviewer_user_id
        JOIN interview_phases p ON p.id = pi.phase_id
        WHERE p.vacancy_id = ?
        ORDER BY pi.phase_id ASC, COALESCE(u.full_name, u.email_address) ASC
        """,
        (job_id,),
    ).fetchall()

    assigned_map: Dict[int, List[int]] = {}
    assigned_labels_map: Dict[int, List[str]] = {}

    for r in assignments_rows:
        pid = int(r["phase_id"])
        assigned_map.setdefault(pid, []).append(int(r["interviewer_id"]))
        # FIX: avoid "email (email)" when full_name is missing
        label = f"{r['full_name']} ({r['email_address']})" if (r["full_name"] or "").strip() else r["email_address"]
        assigned_labels_map.setdefault(pid, []).append(label)

    first_phase_id = get_first_active_phase_id(database_connection, job_id)

    database_connection.close()

    return render_template(
        "manager_phase_interviewers.html",
        job=job,
        phases=phases,
        interviewers=interviewers,
        assigned_map=assigned_map,
        assigned_labels_map=assigned_labels_map,
        first_phase_id=first_phase_id,
    )


@app.route("/manager/phases/<int:phase_id>/phase-interviewers/update", methods=["POST"])
def manager_update_phase_interviewers_action(phase_id: int):
    if not require_role(ROLE_MANAGER):
        return redirect(url_for("dashboard_page"))

    selected_ids = request.form.getlist("interviewer_ids")  # multi-select checkboxes

    database_connection = get_database_connection()

    phase = database_connection.execute(
        """
        SELECT p.id, p.vacancy_id, p.phase_name, p.sequence_number, v.manager_id
        FROM interview_phases p
        JOIN vacancies v ON v.id = p.vacancy_id
        WHERE p.id = ?
        """,
        (phase_id,),
    ).fetchone()

    if not phase:
        database_connection.close()
        flash("Fase niet gevonden.")
        return redirect(url_for("manager_job_postings_page"))

    if int(phase["manager_id"]) != int(session["user_id"]):
        database_connection.close()
        flash("Je hebt geen toegang tot deze fase.")
        return redirect(url_for("manager_job_postings_page"))

    vacancy_id = int(phase["vacancy_id"])
    first_phase_id = get_first_active_phase_id(database_connection, vacancy_id)

    if first_phase_id is not None and int(phase_id) == int(first_phase_id):
        database_connection.close()
        flash("Voor fase 1 wordt de interviewer automatisch de recruiter/admin die het gesprek inplant.")
        return redirect(url_for("manager_phase_interviewers_page", job_id=vacancy_id))

    old_rows = database_connection.execute(
        "SELECT interviewer_user_id FROM phase_interviewers WHERE phase_id = ? ORDER BY interviewer_user_id ASC",
        (phase_id,),
    ).fetchall()
    old_ids = [int(r["interviewer_user_id"]) for r in old_rows]

    cleaned_ids: List[int] = []
    for raw in selected_ids:
        try:
            iid = int(raw)
        except Exception:
            continue
        ok = database_connection.execute(
            "SELECT 1 FROM users WHERE id = ? AND user_role = ? AND is_active = 1 LIMIT 1",
            (iid, ROLE_INTERVIEWER),
        ).fetchone()
        if ok:
            cleaned_ids.append(iid)

    cleaned_ids = sorted(list(set(cleaned_ids)))

    database_connection.execute("DELETE FROM phase_interviewers WHERE phase_id = ?", (phase_id,))
    for iid in cleaned_ids:
        database_connection.execute(
            """
            INSERT INTO phase_interviewers (phase_id, interviewer_user_id)
            VALUES (?, ?)
            """,
            (phase_id, iid),
        )

    log_audit_event(
        database_connection,
        event_type="phase_interviewers_updated",
        entity_type="interview_phase",
        entity_id=int(phase_id),
        details={
            "vacancy_id": vacancy_id,
            "phase_name": phase["phase_name"],
            "sequence_number": int(phase["sequence_number"]),
            "from_interviewer_ids": old_ids,
            "to_interviewer_ids": cleaned_ids,
        },
        performed_by_user_id=session.get("user_id"),
    )

    database_connection.commit()
    database_connection.close()

    flash("Interviewer-toewijzingen opgeslagen.")
    return redirect(url_for("manager_phase_interviewers_page", job_id=vacancy_id))



# ============================================================
# Recruiter: manage interview phases per job posting
# ============================================================

@app.route("/recruiter/job-postings/<int:job_id>/phases")
def recruiter_manage_phases_page(job_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    job = database_connection.execute(
        """
        SELECT v.*, u.email_address AS manager_email
        FROM vacancies v
        JOIN users u ON u.id = v.manager_id
        WHERE v.id = ?
        """,
        (job_id,),
    ).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("recruiter_review_queue_page"))

    phases = database_connection.execute(
        """
        SELECT p.id,
               p.phase_name,
               p.sequence_number,
               p.template_version_id,
               p.is_active,
               tv.version_number AS template_version_number,
               tv.version_label AS template_version_label,
               tv.status AS template_status,
               tg.template_name AS template_group_name,
               (
                 SELECT COUNT(*)
                 FROM template_aspects ta
                 WHERE ta.template_version_id = p.template_version_id
               ) AS aspect_count
        FROM interview_phases p
        LEFT JOIN template_versions tv ON tv.id = p.template_version_id
        LEFT JOIN template_groups tg ON tg.id = tv.template_group_id
        WHERE p.vacancy_id = ?
        ORDER BY p.sequence_number ASC
        """,
        (job_id,),
    ).fetchall()

    published_templates = database_connection.execute(
        """
        SELECT tv.id,
               tg.template_name AS template_name,
               tv.version_number,
               tv.version_label
        FROM template_versions tv
        JOIN template_groups tg ON tg.id = tv.template_group_id
        WHERE tv.status = 'published'
        ORDER BY tg.template_name ASC, tv.version_number DESC
        """
    ).fetchall()

    database_connection.close()

    return render_template(
        "phases_manage.html",
        job=job,
        phases=phases,
        published_templates=published_templates,
        status_labels=JOB_STATUS_LABELS,
    )


@app.route("/recruiter/job-postings/<int:job_id>/phases/create", methods=["POST"])
def recruiter_create_phase_action(job_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    phase_name = (request.form.get("phase_name") or "").strip()
    sequence_number_raw = (request.form.get("sequence_number") or "").strip()
    template_version_id_raw = (request.form.get("template_version_id") or "").strip()

    is_active_raw = (request.form.get("is_active") or "1").strip()
    is_active = 1 if is_active_raw == "1" else 0

    if not phase_name:
        flash("Phase name is required.")
        return redirect(url_for("recruiter_manage_phases_page", job_id=job_id))

    try:
        template_version_id = int(template_version_id_raw)
    except Exception:
        flash("Selecteer een (gepubliceerde) evaluatietemplate.")
        return redirect(url_for("recruiter_manage_phases_page", job_id=job_id))

    database_connection = get_database_connection()

    job = database_connection.execute("SELECT id FROM vacancies WHERE id = ?", (job_id,)).fetchone()
    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("recruiter_review_queue_page"))

    tv = database_connection.execute(
        "SELECT id, status FROM template_versions WHERE id = ?",
        (template_version_id,),
    ).fetchone()
    if not tv or (tv["status"] or "") != "published":
        database_connection.close()
        flash("Kies een gepubliceerde templateversie.")
        return redirect(url_for("recruiter_manage_phases_page", job_id=job_id))

    if sequence_number_raw:
        try:
            sequence_number = int(sequence_number_raw)
            if sequence_number <= 0:
                raise ValueError
        except Exception:
            database_connection.close()
            flash("Volgnummer moet een positief geheel getal zijn (of laat leeg voor automatisch).")
            return redirect(url_for("recruiter_manage_phases_page", job_id=job_id))
    else:
        max_row = database_connection.execute(
            """
            SELECT COALESCE(MAX(sequence_number), 0) AS max_seq
            FROM interview_phases
            WHERE vacancy_id = ?
            """,
            (job_id,),
        ).fetchone()
        sequence_number = int(max_row["max_seq"] or 0) + 1

    existing_seq = database_connection.execute(
        """
        SELECT 1
        FROM interview_phases
        WHERE vacancy_id = ? AND sequence_number = ?
        LIMIT 1
        """,
        (job_id, sequence_number),
    ).fetchone()
    if existing_seq:
        database_connection.close()
        flash("Er bestaat al een fase met dit volgnummer. Kies een ander nummer (of laat leeg).")
        return redirect(url_for("recruiter_manage_phases_page", job_id=job_id))

    cur = database_connection.execute(
        """
        INSERT INTO interview_phases (vacancy_id, phase_name, sequence_number, template_version_id, is_active)
        VALUES (?, ?, ?, ?, ?)
        """,
        (job_id, phase_name, sequence_number, template_version_id, is_active),
    )

    log_audit_event(
        database_connection,
        event_type="phase_created",
        entity_type="interview_phase",
        entity_id=int(cur.lastrowid),
        details={
            "vacancy_id": job_id,
            "phase_name": phase_name,
            "sequence_number": sequence_number,
            "template_version_id": template_version_id,
            "is_active": is_active,
        },
        performed_by_user_id=session.get("user_id"),
    )

    database_connection.commit()
    database_connection.close()

    flash("Interviewfase toegevoegd.")
    return redirect(url_for("recruiter_manage_phases_page", job_id=job_id))


@app.route("/recruiter/phases/<int:phase_id>/edit")
def recruiter_edit_phase_page(phase_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    phase = database_connection.execute(
        """
        SELECT p.*, v.title AS vacancy_title, v.id AS vacancy_id, v.status AS vacancy_status, u.email_address AS manager_email
        FROM interview_phases p
        JOIN vacancies v ON v.id = p.vacancy_id
        JOIN users u ON u.id = v.manager_id
        WHERE p.id = ?
        """,
        (phase_id,),
    ).fetchone()

    if not phase:
        database_connection.close()
        flash("Fase niet gevonden.")
        return redirect(url_for("recruiter_review_queue_page"))

    job = {
        "id": phase["vacancy_id"],
        "title": phase["vacancy_title"],
        "manager_email": phase["manager_email"],
        "status": phase["vacancy_status"],
    }

    published_templates = database_connection.execute(
        """
        SELECT tv.id, tg.template_name, tv.version_number, tv.version_label, tv.status
        FROM template_versions tv
        JOIN template_groups tg ON tg.id = tv.template_group_id
        WHERE tv.status = 'published'
        ORDER BY tg.template_name ASC, tv.version_number DESC
        """
    ).fetchall()

    current_tv = database_connection.execute(
        """
        SELECT tv.id, tg.template_name, tv.version_number, tv.version_label, tv.status
        FROM template_versions tv
        JOIN template_groups tg ON tg.id = tv.template_group_id
        WHERE tv.id = ?
        """,
        (phase["template_version_id"],),
    ).fetchone()

    database_connection.close()

    return render_template(
        "phase_edit.html",
        job=job,
        phase=phase,
        published_templates=published_templates,
        current_template=current_tv,
        status_labels=JOB_STATUS_LABELS,
    )


@app.route("/recruiter/phases/<int:phase_id>/update", methods=["POST"])
def recruiter_update_phase_action(phase_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    phase_name = (request.form.get("phase_name") or "").strip()
    sequence_number_raw = (request.form.get("sequence_number") or "").strip()
    template_version_id_raw = (request.form.get("template_version_id") or "").strip()
    is_active_raw = (request.form.get("is_active") or "0").strip()

    if not phase_name:
        flash("Phase name is required.")
        return redirect(url_for("recruiter_edit_phase_page", phase_id=phase_id))

    try:
        sequence_number = int(sequence_number_raw)
        if sequence_number <= 0:
            raise ValueError
    except Exception:
        flash("Sequence number must be a positive integer.")
        return redirect(url_for("recruiter_edit_phase_page", phase_id=phase_id))

    try:
        template_version_id = int(template_version_id_raw)
    except Exception:
        flash("Selecteer een (gepubliceerde) evaluatietemplate.")
        return redirect(url_for("recruiter_edit_phase_page", phase_id=phase_id))

    is_active = 1 if is_active_raw == "1" else 0

    database_connection = get_database_connection()

    phase = database_connection.execute(
        """
        SELECT id, vacancy_id, phase_name, sequence_number, template_version_id, is_active
        FROM interview_phases
        WHERE id = ?
        """,
        (phase_id,),
    ).fetchone()

    if not phase:
        database_connection.close()
        flash("Fase niet gevonden.")
        return redirect(url_for("recruiter_review_queue_page"))

    tv = database_connection.execute(
        "SELECT id, status FROM template_versions WHERE id = ?",
        (template_version_id,),
    ).fetchone()
    if not tv or (tv["status"] or "") != "published":
        database_connection.close()
        flash("Kies een gepubliceerde templateversie.")
        return redirect(url_for("recruiter_edit_phase_page", phase_id=phase_id))

    try:
        database_connection.execute(
            """
            UPDATE interview_phases
            SET phase_name = ?, sequence_number = ?, template_version_id = ?, is_active = ?
            WHERE id = ?
            """,
            (phase_name, sequence_number, template_version_id, is_active, phase_id),
        )
    except sqlite3.IntegrityError:
        database_connection.close()
        flash("Er bestaat al een fase met dit volgnummer voor deze vacature.")
        return redirect(url_for("recruiter_edit_phase_page", phase_id=phase_id))

    log_audit_event(
        database_connection,
        event_type="phase_updated",
        entity_type="interview_phase",
        entity_id=int(phase_id),
        details={
            "vacancy_id": int(phase["vacancy_id"]),
            "from": {
                "phase_name": phase["phase_name"],
                "sequence_number": int(phase["sequence_number"]),
                "template_version_id": int(phase["template_version_id"]),
                "is_active": int(phase["is_active"]),
            },
            "to": {
                "phase_name": phase_name,
                "sequence_number": sequence_number,
                "template_version_id": template_version_id,
                "is_active": is_active,
            },
        },
        performed_by_user_id=session.get("user_id"),
    )

    database_connection.commit()
    database_connection.close()

    flash("Interviewfase bijgewerkt.")
    return redirect(url_for("recruiter_manage_phases_page", job_id=int(phase["vacancy_id"])))


@app.route("/job-postings/<int:job_id>")
def job_posting_detail_page(job_id: int):
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    if not require_any_role([ROLE_MANAGER, ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    job = database_connection.execute(
        """
        SELECT v.*,
               u.email_address AS manager_email
        FROM vacancies v
        JOIN users u ON u.id = v.manager_id
        WHERE v.id = ?
        """,
        (job_id,),
    ).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("dashboard_page"))

    if session.get("user_role") == ROLE_MANAGER and job["manager_id"] != session["user_id"]:
        database_connection.close()
        flash("You do not have access to this job posting.")
        return redirect(url_for("manager_job_postings_page"))

    phases = database_connection.execute(
        """
        SELECT p.id,
               p.phase_name,
               p.sequence_number,
               p.template_version_id,
               p.is_active,
               tv.version_number AS template_version_number,
               tv.version_label AS template_version_label,
               tv.status AS template_status,
               tg.template_name AS template_group_name,
               (
                 SELECT COUNT(*)
                 FROM template_aspects ta
                 WHERE ta.template_version_id = p.template_version_id
               ) AS aspect_count
        FROM interview_phases p
        LEFT JOIN template_versions tv ON tv.id = p.template_version_id
        LEFT JOIN template_groups tg ON tg.id = tv.template_group_id
        WHERE p.vacancy_id = ?
        ORDER BY p.sequence_number ASC
        """,
        (job_id,),
    ).fetchall()

    publish_checks = None
    if session.get("user_role") in {ROLE_RECRUITER, ROLE_ADMIN} and job["status"] == JOB_STATUS_PENDING_REVIEW:
        publish_checks = build_publish_checks(database_connection, job_id)

    database_connection.close()

    return render_template(
        "job_posting_detail.html",
        job=job,
        phases=phases,
        publish_checks=publish_checks,
        status_labels=JOB_STATUS_LABELS,
    )


@app.route("/manager/job-postings/<int:job_id>/edit", methods=["GET", "POST"])
def edit_job_posting_page(job_id: int):
    if not require_role(ROLE_MANAGER):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    job = database_connection.execute(
        "SELECT * FROM vacancies WHERE id = ? AND manager_id = ?",
        (job_id, session["user_id"]),
    ).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("manager_job_postings_page"))

    if request.method == "POST":
        title = request.form.get("vacancy_title", "").strip()
        department = request.form.get("vacancy_department", "").strip()
        description = request.form.get("vacancy_description", "").strip()

        location = request.form.get("vacancy_location", "").strip() or None
        employment_type = request.form.get("employment_type", "").strip() or None
        experience_level = request.form.get("experience_level", "").strip() or None

        if not title or not department or not description:
            database_connection.close()
            flash("Please fill in title, department and description.")
            return render_template("edit_vacancy.html", job=job, status_labels=JOB_STATUS_LABELS)

        new_status = job["status"]
        new_submitted_at = job["submitted_at"]

        if job["status"] == JOB_STATUS_CHANGES_REQUESTED:
            new_status = JOB_STATUS_DRAFT
            new_submitted_at = None

        database_connection.execute(
            """
            UPDATE vacancies
            SET title = ?,
                department = ?,
                description = ?,
                location = ?,
                employment_type = ?,
                experience_level = ?,
                status = ?,
                submitted_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND manager_id = ?
            """,
            (
                title,
                department,
                description,
                location,
                employment_type,
                experience_level,
                new_status,
                new_submitted_at,
                job_id,
                session["user_id"],
            ),
        )

        log_audit_event(
            database_connection,
            event_type="vacancy_updated",
            entity_type="vacancy",
            entity_id=job_id,
            from_status=job["status"],
            to_status=new_status,
            performed_by_user_id=session["user_id"],
        )

        database_connection.commit()
        database_connection.close()

        flash(
            "Changes saved. Status set back to Draft — you can now submit again for review."
            if job["status"] == JOB_STATUS_CHANGES_REQUESTED
            else "Job posting updated."
        )
        return redirect(url_for("manager_job_postings_page"))

    database_connection.close()
    return render_template("edit_vacancy.html", job=job, status_labels=JOB_STATUS_LABELS)



# ============================================================
# 5) Recruiter: review + publish + close vacancies
# ============================================================

@app.route("/recruiter/job-postings")
def recruiter_review_queue_page():
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    queue = database_connection.execute(
        """
        SELECT v.*,
               u.email_address AS manager_email
        FROM vacancies v
        JOIN users u ON u.id = v.manager_id
        WHERE v.status IN (?, ?, ?, ?)
        ORDER BY
            CASE v.status
                WHEN ? THEN 1
                WHEN ? THEN 2
                WHEN ? THEN 3
                WHEN ? THEN 4
                ELSE 99
            END,
            v.submitted_at DESC,
            v.created_at DESC
        """,
        (
            JOB_STATUS_PENDING_REVIEW,
            JOB_STATUS_PUBLISHED,
            JOB_STATUS_CHANGES_REQUESTED,
            JOB_STATUS_CLOSED,
            JOB_STATUS_PENDING_REVIEW,
            JOB_STATUS_CHANGES_REQUESTED,
            JOB_STATUS_PUBLISHED,
            JOB_STATUS_CLOSED,
        ),
    ).fetchall()
    database_connection.close()

    return render_template("review_queue.html", jobs=queue, status_labels=JOB_STATUS_LABELS)


@app.route("/recruiter/job-postings/<int:job_id>/publish", methods=["POST"])
def publish_job_posting_action(job_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    job = database_connection.execute("SELECT * FROM vacancies WHERE id = ?", (job_id,)).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("recruiter_review_queue_page"))

    if job["status"] != JOB_STATUS_PENDING_REVIEW:
        database_connection.close()
        flash("Only pending review job postings can be published.")
        return redirect(url_for("recruiter_review_queue_page"))

    publish_checks = build_publish_checks(database_connection, job_id)
    if not publish_checks["is_ready"]:
        database_connection.close()
        flash("Cannot publish yet. Please fix: " + " | ".join(publish_checks["missing_items"]))
        return redirect(url_for("job_posting_detail_page", job_id=job_id))

    previous_status = job["status"]

    database_connection.execute(
        """
        UPDATE vacancies
        SET status = ?,
            reviewed_by_user_id = ?,
            reviewed_at = CURRENT_TIMESTAMP,
            published_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (JOB_STATUS_PUBLISHED, session["user_id"], job_id),
    )

    log_audit_event(
        database_connection,
        event_type="vacancy_published",
        entity_type="vacancy",
        entity_id=job_id,
        from_status=previous_status,
        to_status=JOB_STATUS_PUBLISHED,
        performed_by_user_id=session["user_id"],
    )

    database_connection.commit()
    database_connection.close()

    flash("Job posting published.")
    return redirect(url_for("recruiter_review_queue_page"))


@app.route("/recruiter/job-postings/<int:job_id>/request-changes", methods=["POST"])
def request_changes_job_posting_action(job_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    review_comment = request.form.get("review_comment", "").strip()

    database_connection = get_database_connection()
    job = database_connection.execute("SELECT * FROM vacancies WHERE id = ?", (job_id,)).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("recruiter_review_queue_page"))

    if job["status"] != JOB_STATUS_PENDING_REVIEW:
        database_connection.close()
        flash("Only pending review job postings can receive a change request.")
        return redirect(url_for("recruiter_review_queue_page"))

    previous_status = job["status"]

    database_connection.execute(
        """
        UPDATE vacancies
        SET status = ?,
            review_comment = ?,
            reviewed_by_user_id = ?,
            reviewed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (JOB_STATUS_CHANGES_REQUESTED, review_comment if review_comment else None, session["user_id"], job_id),
    )

    log_audit_event(
        database_connection,
        event_type="vacancy_changes_requested",
        entity_type="vacancy",
        entity_id=job_id,
        from_status=previous_status,
        to_status=JOB_STATUS_CHANGES_REQUESTED,
        details={"comment": review_comment} if review_comment else {},
        performed_by_user_id=session["user_id"],
    )

    database_connection.commit()
    database_connection.close()

    flash("Changes requested from manager.")
    return redirect(url_for("recruiter_review_queue_page"))


@app.route("/recruiter/job-postings/<int:job_id>/close", methods=["POST"])
def close_job_posting_action(job_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    job = database_connection.execute("SELECT * FROM vacancies WHERE id = ?", (job_id,)).fetchone()

    if not job:
        database_connection.close()
        flash("Job posting not found.")
        return redirect(url_for("recruiter_review_queue_page"))

    previous_status = job["status"]

    database_connection.execute(
        """
        UPDATE vacancies
        SET status = ?,
            closed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (JOB_STATUS_CLOSED, job_id),
    )

    log_audit_event(
        database_connection,
        event_type="vacancy_closed",
        entity_type="vacancy",
        entity_id=job_id,
        from_status=previous_status,
        to_status=JOB_STATUS_CLOSED,
        performed_by_user_id=session["user_id"],
    )

    database_connection.commit()
    database_connection.close()

    flash("Job posting closed.")
    return redirect(url_for("recruiter_review_queue_page"))



# ============================================================
# 6) Recruiter: applications + statuses + interview planning
# ============================================================

@app.route("/recruiter/sollicitaties")
def recruiter_applications_page():
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    search_query = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "all").strip()
    vacancy_filter = request.args.get("vacancy_id", "all").strip()

    database_connection = get_database_connection()

    status_options = [
        ("all", "All"),
        (APP_STATUS_NEW, APP_STATUS_LABELS[APP_STATUS_NEW]),
        (APP_STATUS_IN_REVIEW, APP_STATUS_LABELS[APP_STATUS_IN_REVIEW]),
        (APP_STATUS_SHORTLISTED, APP_STATUS_LABELS[APP_STATUS_SHORTLISTED]),
        (APP_STATUS_INTERVIEW, APP_STATUS_LABELS[APP_STATUS_INTERVIEW]),
        (APP_STATUS_REJECTED, APP_STATUS_LABELS[APP_STATUS_REJECTED]),
        (APP_STATUS_OFFERED, APP_STATUS_LABELS[APP_STATUS_OFFERED]),
        (APP_STATUS_HIRED, APP_STATUS_LABELS[APP_STATUS_HIRED]),
        (APP_STATUS_WITHDRAWN, APP_STATUS_LABELS[APP_STATUS_WITHDRAWN]),
    ]

    vacancy_options = database_connection.execute(
        """
        SELECT DISTINCT v.id, v.title
        FROM applications a
        JOIN vacancies v ON a.vacancy_id = v.id
        ORDER BY v.title ASC
        """
    ).fetchall()

    where_clauses = []
    params: List[Any] = []

    if search_query:
        where_clauses.append("(c.full_name LIKE ? OR c.email_address LIKE ?)")
        like_value = f"%{search_query}%"
        params.extend([like_value, like_value])

    if status_filter and status_filter != "all":
        if status_filter in ALLOWED_APPLICATION_STATUSES:
            where_clauses.append("a.status = ?")
            params.append(status_filter)

    if vacancy_filter and vacancy_filter != "all":
        try:
            vacancy_id_int = int(vacancy_filter)
            where_clauses.append("a.vacancy_id = ?")
            params.append(vacancy_id_int)
        except ValueError:
            pass

    sql = """
        SELECT
            a.id,
            a.applied_at,
            a.status AS app_status,
            c.full_name AS candidate_name,
            c.email_address AS candidate_email,
            a.resume_storage_filename AS cv_path,
            v.title AS vacancy_title,
            (
                SELECT i.status
                FROM interviews i
                WHERE i.application_id = a.id
                ORDER BY i.scheduled_start DESC
                LIMIT 1
            ) AS interview_status
        FROM applications a
        JOIN candidates c ON a.candidate_id = c.id
        JOIN vacancies v ON a.vacancy_id = v.id
    """

    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)

    sql += " ORDER BY a.applied_at DESC"

    applications = database_connection.execute(sql, tuple(params)).fetchall()
    database_connection.close()

    return render_template(
        "recruiter_applications.html",
        applications=applications,
        status_labels=APP_STATUS_LABELS,
        status_options=status_options,
        vacancy_options=vacancy_options,
        selected_status=status_filter,
        selected_vacancy_id=vacancy_filter,
        search_query=search_query,
    )

@app.route("/recruiter/applications/<int:application_id>/interviews")
def recruiter_application_interviews_page(application_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_MANAGER, ROLE_ADMIN, ROLE_INTERVIEWER]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    application = database_connection.execute(
        """
        SELECT
            a.id,
            a.status AS app_status,
            a.applied_at,
            c.full_name AS candidate_name,
            c.email_address AS candidate_email,
            a.resume_storage_filename AS cv_path,
            v.id AS vacancy_id,
            v.title AS vacancy_title,
            v.manager_id AS manager_id
        FROM applications a
        JOIN candidates c ON a.candidate_id = c.id
        JOIN vacancies v ON a.vacancy_id = v.id
        WHERE a.id = ?
        """,
        (application_id,),
    ).fetchone()

    if not application:
        database_connection.close()
        flash("Application not found.")
        return redirect(url_for("recruiter_applications_page"))

    user_role = session.get("user_role")
    user_id = int(session.get("user_id"))

    # Access rules:
    # - recruiter/admin: altijd ok
    # - manager: enkel als owner manager van vacature
    # - interviewer: enkel als hij/zij interviewer is van minstens 1 interview in deze application
    if user_role == ROLE_MANAGER:
        if int(application["manager_id"]) != user_id:
            database_connection.close()
            flash("You do not have access to this application.")
            return redirect(url_for("manager_job_postings_page"))

    if user_role == ROLE_INTERVIEWER:
        has_access = database_connection.execute(
            """
            SELECT 1
            FROM interviews i
            JOIN interview_interviewers ii ON ii.interview_id = i.id
            WHERE i.application_id = ? AND ii.interviewer_user_id = ?
            LIMIT 1
            """,
            (application_id, user_id),
        ).fetchone()
        if not has_access:
            database_connection.close()
            flash("You do not have access to this application.")
            return redirect(url_for("my_interviews_page"))

    interviews = database_connection.execute(
        """
        SELECT
            i.id,
            i.status AS interview_status,
            i.scheduled_start,
            i.meeting_link,
            p.sequence_number,
            p.phase_name,

            (
                SELECT GROUP_CONCAT(
                    COALESCE(u.full_name, 'User') || ' (' || u.email_address || ', ' || ii2.interviewer_role || ')',
                    ' | '
                )
                FROM interview_interviewers ii2
                JOIN users u ON u.id = ii2.interviewer_user_id
                WHERE ii2.interview_id = i.id
            ) AS interviewer_list,

            (
                SELECT COUNT(*)
                FROM interview_interviewers ii3
                WHERE ii3.interview_id = i.id
            ) AS interviewer_count,

            (
                SELECT COALESCE(SUM(CASE WHEN e.evaluation_status = 'submitted' THEN 1 ELSE 0 END), 0)
                FROM evaluations e
                WHERE e.interview_id = i.id
            ) AS submitted_count,

            EXISTS (
                SELECT 1
                FROM interview_interviewers iim
                WHERE iim.interview_id = i.id
                  AND iim.interviewer_user_id = ?
            ) AS can_evaluate,

            (
                SELECT e.evaluation_status
                FROM evaluations e
                WHERE e.interview_id = i.id
                  AND e.interviewer_user_id = ?
                ORDER BY e.updated_at DESC, e.id DESC
                LIMIT 1
            ) AS my_evaluation_status

        FROM interviews i
        LEFT JOIN interview_phases p ON p.id = i.phase_id
        WHERE i.application_id = ?
        ORDER BY COALESCE(p.sequence_number, 999) ASC, i.scheduled_start ASC
        """,
        (user_id, user_id, application_id),
    ).fetchall()

    database_connection.close()

    return render_template(
        "application_interviews.html",
        application=application,
        interviews=interviews,
        status_labels=APP_STATUS_LABELS,
    )



@app.route("/recruiter/applications/<int:application_id>/status", methods=["POST"])
def recruiter_update_application_status_action(application_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    new_status = request.form.get("new_status", "").strip()
    new_status = get_safe_choice(new_status, list(ALLOWED_APPLICATION_STATUSES), APP_STATUS_NEW)

    database_connection = get_database_connection()

    application = database_connection.execute(
        "SELECT id, status FROM applications WHERE id = ?",
        (application_id,),
    ).fetchone()

    if not application:
        database_connection.close()
        flash("Application not found.")
        return redirect(url_for("recruiter_applications_page"))

    old_status = application["status"]

    if old_status in FINAL_APPLICATION_STATUSES:
        database_connection.close()
        flash("This application is already final and cannot be changed.")
        return redirect(url_for("recruiter_applications_page"))

    database_connection.execute(
        """
        UPDATE applications
        SET status = ?,
            status_updated_at = CURRENT_TIMESTAMP,
            status_updated_by_user_id = ?,
            status_updated_by_candidate_id = NULL
        WHERE id = ?
        """,
        (new_status, session["user_id"], application_id),
    )

    log_audit_event(
        database_connection,
        event_type="application_status_changed",
        entity_type="application",
        entity_id=application_id,
        from_status=old_status,
        to_status=new_status,
        performed_by_user_id=session["user_id"],
    )

    database_connection.commit()
    database_connection.close()

    flash(f"Application status updated to: {APP_STATUS_LABELS.get(new_status, new_status)}")
    return redirect(url_for("recruiter_applications_page"))


@app.route("/plan-interview/<int:application_id>", methods=["GET", "POST"])
def plan_interview_page(application_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    # -------------------------
    # POST: interview plannen + mail sturen
    # -------------------------
    if request.method == "POST":
        planned_datetime_raw = request.form.get("interview_date", "").strip()
        planned_datetime = normalize_datetime_local(planned_datetime_raw)

        selected_phase_id_raw = request.form.get("phase_id", "").strip()

        selected_interviewer_ids_raw = request.form.getlist("selected_interviewers")
        if not selected_interviewer_ids_raw:
            legacy_single = (request.form.get("selected_interviewer") or "").strip()
            if legacy_single:
                selected_interviewer_ids_raw = [legacy_single]

        teams_link = (request.form.get("teams_link") or "").strip() or None

        if not planned_datetime or not selected_phase_id_raw:
            database_connection.close()
            flash("Selecteer een fase en een datum/tijd.")
            return redirect(url_for("plan_interview_page", application_id=application_id))

        application_status_row = database_connection.execute(
            "SELECT id, status, vacancy_id, candidate_id FROM applications WHERE id = ?",
            (application_id,),
        ).fetchone()

        if not application_status_row:
            database_connection.close()
            flash("Application not found.")
            return redirect(url_for("recruiter_applications_page"))

        if application_status_row["status"] in FINAL_APPLICATION_STATUSES:
            database_connection.close()
            flash("Cannot plan an interview for a final application.")
            return redirect(url_for("recruiter_applications_page"))

        try:
            phase_id = int(selected_phase_id_raw)
        except ValueError:
            database_connection.close()
            flash("Ongeldige fase.")
            return redirect(url_for("plan_interview_page", application_id=application_id))

        phase_row = database_connection.execute(
            """
            SELECT id, vacancy_id, sequence_number
            FROM interview_phases
            WHERE id = ? AND vacancy_id = ? AND is_active = 1
            """,
            (phase_id, application_status_row["vacancy_id"]),
        ).fetchone()

        if not phase_row:
            database_connection.close()
            flash("Deze fase bestaat niet (of is niet actief) voor deze vacature.")
            return redirect(url_for("plan_interview_page", application_id=application_id))

        vacancy_id_int = int(application_status_row["vacancy_id"])
        first_phase_id = get_first_active_phase_id(database_connection, vacancy_id_int)

        interviewer_user_ids = []
        primary_interviewer_user_id = None

        if first_phase_id is not None and phase_id == first_phase_id:
            primary_interviewer_user_id = int(session["user_id"])
            interviewer_user_ids = [primary_interviewer_user_id]
        else:
            assigned_rows = get_assigned_interviewers_for_phase(database_connection, phase_id)
            assigned_ids = {int(u["id"]) for u in assigned_rows}

            if not assigned_ids:
                database_connection.close()
                flash("Voor deze fase zijn nog geen interviewers toegewezen door de Hiring Manager.")
                return redirect(url_for("plan_interview_page", application_id=application_id))

            if not selected_interviewer_ids_raw:
                database_connection.close()
                flash("Selecteer minstens één interviewer (toegewezen door de Hiring Manager).")
                return redirect(url_for("plan_interview_page", application_id=application_id))

            parsed = []
            for raw in selected_interviewer_ids_raw:
                try:
                    iid = int((raw or "").strip())
                except Exception:
                    database_connection.close()
                    flash("Invalid interviewer selected.")
                    return redirect(url_for("plan_interview_page", application_id=application_id))

                if iid not in parsed:
                    parsed.append(iid)

            invalid = [iid for iid in parsed if iid not in assigned_ids]
            if invalid:
                database_connection.close()
                flash("Je kan enkel interviewers kiezen die door de Hiring Manager aan deze fase zijn toegewezen.")
                return redirect(url_for("plan_interview_page", application_id=application_id))

            interviewer_user_ids = parsed
            primary_interviewer_user_id = interviewer_user_ids[0]

        cursor = database_connection.cursor()
        cursor.execute(
            """
            INSERT INTO interviews (
                application_id, phase_id,
                scheduled_start, scheduled_end,
                location, meeting_link,
                status, created_by_user_id, created_at
            )
            VALUES (?, ?, ?, NULL, NULL, ?, 'planned', ?, CURRENT_TIMESTAMP)
            """,
            (application_id, phase_id, planned_datetime, teams_link, session["user_id"]),
        )
        interview_id = cursor.lastrowid

        to_insert = []
        for iid in interviewer_user_ids:
            role = "primary" if iid == primary_interviewer_user_id else "panel"
            to_insert.append((interview_id, iid, role))

        cursor.executemany(
            """
            INSERT INTO interview_interviewers (interview_id, interviewer_user_id, interviewer_role)
            VALUES (?, ?, ?)
            """,
            to_insert,
        )

        previous_status = application_status_row["status"]
        database_connection.execute(
            """
            UPDATE applications
            SET status = ?,
                status_updated_at = CURRENT_TIMESTAMP,
                status_updated_by_user_id = ?,
                status_updated_by_candidate_id = NULL
            WHERE id = ?
            """,
            (APP_STATUS_INTERVIEW, session["user_id"], application_id),
        )

        log_audit_event(
            database_connection,
            event_type="interview_planned",
            entity_type="interview",
            entity_id=interview_id,
            details={
                "application_id": application_id,
                "phase_id": phase_id,
                "interviewer_user_ids": interviewer_user_ids,
                "primary_interviewer_user_id": primary_interviewer_user_id,
                "auto_assigned_recruiter_for_phase1": bool(first_phase_id is not None and phase_id == first_phase_id),
                "meeting_link": teams_link,
            },
            performed_by_user_id=session["user_id"],
        )

        if previous_status != APP_STATUS_INTERVIEW:
            log_audit_event(
                database_connection,
                event_type="application_status_changed",
                entity_type="application",
                entity_id=application_id,
                from_status=previous_status,
                to_status=APP_STATUS_INTERVIEW,
                performed_by_user_id=session["user_id"],
            )

        info = database_connection.execute(
            """
            SELECT
                c.full_name AS candidate_name,
                c.email_address AS candidate_email,
                c.password_hash AS candidate_password_hash,
                a.status_view_token AS status_view_token,
                v.title AS vacancy_title,
                p.phase_name AS phase_name
            FROM applications a
            JOIN candidates c ON c.id = a.candidate_id
            JOIN vacancies v ON v.id = a.vacancy_id
            LEFT JOIN interview_phases p ON p.id = ?
            WHERE a.id = ?
            """,
            (phase_id, application_id),
        ).fetchone()

        database_connection.commit()
        database_connection.close()

        try:
            if info:
                candidate_name_mail = (info["candidate_name"] or "kandidaat").strip()
                candidate_email_mail = (info["candidate_email"] or "").strip()
                vacancy_title_mail = info["vacancy_title"] or "Vacature"
                phase_name_mail = info["phase_name"] or "Interviewfase"
                status_token = info["status_view_token"]

                if candidate_email_mail:
                    status_url_external = url_for(
                        "application_status_page",
                        token=status_token,
                        _external=True,
                    )

                    when_text = format_datetime_for_email(planned_datetime)

                    set_pw_external = None
                    if not info["candidate_password_hash"]:
                        token_pw = create_set_password_token()
                        expires_pw = set_password_expiry(hours=24)

                        db_tmp = get_database_connection()
                        db_tmp.execute(
                            """
                            UPDATE candidates
                            SET set_password_token = ?,
                                set_password_expires_at = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE email_address = ?
                            """,
                            (token_pw, expires_pw, candidate_email_mail),
                        )
                        db_tmp.commit()
                        db_tmp.close()

                        set_pw_external = url_for(
                            "candidate_set_password_page",
                            token=token_pw,
                            next=status_url_external,
                            _external=True,
                        )

                    subject = f"Uitnodiging interview — {vacancy_title_mail}"

                    lines = [
                        f"Hallo {candidate_name_mail},",
                        "",
                        "Je bent uitgenodigd voor een interview.",
                        f"Vacature: {vacancy_title_mail}",
                        f"Fase: {phase_name_mail}",
                        f"Wanneer: {when_text} (Europe/Brussels)",
                    ]

                    if teams_link:
                        lines += ["", "Teams link:", teams_link]
                    else:
                        lines += ["", "Dit gesprek is fysiek (geen Teams-link opgegeven)."]

                    lines += ["", f"Volg je status hier: {status_url_external}"]

                    if set_pw_external:
                        lines += ["", "Maak je account aan / stel je wachtwoord in via:", set_pw_external]

                    ok, err = send_email(
                        to_email=candidate_email_mail,
                        subject=subject,
                        text_body="\n".join(lines),
                        html_body=None,
                    )
                    if not ok:
                        print("EMAIL ERROR (interview invite):", err)
        except Exception as e:
            print("EMAIL ERROR (interview invite unexpected):", e)

        flash("Interview planned successfully!")
        return redirect(url_for("recruiter_applications_page"))

    # -------------------------
    # GET: pagina tonen + suggested next phase bepalen
    # -------------------------
    application = database_connection.execute(
        """
        SELECT
            a.id,
            a.status,
            c.full_name AS name,
            c.email_address AS email,
            a.resume_storage_filename AS cv_path,
            v.title AS vacancy_title,
            v.id AS vacancy_id
        FROM applications a
        JOIN candidates c ON a.candidate_id = c.id
        JOIN vacancies v ON a.vacancy_id = v.id
        WHERE a.id = ?
        """,
        (application_id,),
    ).fetchone()

    if not application:
        database_connection.close()
        flash("Application not found.")
        return redirect(url_for("recruiter_applications_page"))

    phases = database_connection.execute(
        """
        SELECT id, phase_name, sequence_number
        FROM interview_phases
        WHERE vacancy_id = ? AND is_active = 1
        ORDER BY sequence_number ASC
        """,
        (application["vacancy_id"],),
    ).fetchall()

    vacancy_id_int = int(application["vacancy_id"])
    first_phase_id = get_first_active_phase_id(database_connection, vacancy_id_int)
    phase_interviewers_map = get_phase_interviewer_map_for_vacancy(database_connection, vacancy_id_int)

    if first_phase_id is not None:
        phase_interviewers_map[int(first_phase_id)] = []

    # ✅ Bepaal welke fases al gepland zijn voor deze application
    planned_phase_rows = database_connection.execute(
        """
        SELECT DISTINCT phase_id
        FROM interviews
        WHERE application_id = ?
        """,
        (application_id,),
    ).fetchall()
    planned_phase_ids = {int(r["phase_id"]) for r in planned_phase_rows if r["phase_id"] is not None}

    # ✅ suggested = eerstvolgende actieve fase die nog NIET gepland is
    suggested_phase_id = None
    for ph in phases:
        pid = int(ph["id"])
        if pid not in planned_phase_ids:
            suggested_phase_id = pid
            break

    database_connection.close()

    return render_template(
        "plan_interview.html",
        application=application,
        phases=phases,
        first_phase_id=first_phase_id,
        phase_interviewers_map=phase_interviewers_map,
        suggested_phase_id=suggested_phase_id,
    )


# Recruiter heeft geen "My interviews" functionaliteit:
# deze pagina is enkel voor ROLE_INTERVIEWER.
@app.route("/my-interviews")
def my_interviews_page():
    if not require_any_role([ROLE_INTERVIEWER, ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()
    my_interviews = database_connection.execute(
        """
        SELECT
            i.id,
            i.scheduled_start AS scheduled_start,
            i.status AS status,
            p.phase_name AS phase_name,
            c.full_name AS candidate_name,
            a.resume_storage_filename AS cv_path,
            v.title AS vacancy_title,

            (
                SELECT e.evaluation_status
                FROM evaluations e
                WHERE e.interview_id = i.id
                  AND e.interviewer_user_id = ?
                ORDER BY e.updated_at DESC, e.id DESC
                LIMIT 1
            ) AS evaluation_status

        FROM interviews i
        JOIN applications a ON i.application_id = a.id
        JOIN candidates c ON a.candidate_id = c.id
        JOIN vacancies v ON a.vacancy_id = v.id
        LEFT JOIN interview_phases p ON p.id = i.phase_id
        WHERE EXISTS (
            SELECT 1
            FROM interview_interviewers ii
            WHERE ii.interview_id = i.id
              AND ii.interviewer_user_id = ?
        )
        ORDER BY i.scheduled_start ASC
        """,
        (session["user_id"], session["user_id"]),
    ).fetchall()

    database_connection.close()
    return render_template("my_interviews.html", interviews=my_interviews)


@app.route("/evaluate/<int:interview_id>", methods=["GET", "POST"])
def evaluate_page(interview_id: int):
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    if not require_any_role([ROLE_INTERVIEWER, ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    interview = database_connection.execute(
        """
        SELECT
            i.id,
            i.application_id,
            i.status AS interview_status,
            i.scheduled_start AS scheduled_start,
            p.phase_name AS phase_name,
            p.template_version_id AS template_version_id,
            c.full_name AS candidate_name,
            c.email_address AS candidate_email,
            a.resume_storage_filename AS cv_path,
            v.title AS vacancy_title
        FROM interviews i
        JOIN interview_interviewers ii ON ii.interview_id = i.id
        JOIN interview_phases p ON p.id = i.phase_id
        JOIN applications a ON i.application_id = a.id
        JOIN candidates c ON a.candidate_id = c.id
        JOIN vacancies v ON a.vacancy_id = v.id
        WHERE i.id = ? AND ii.interviewer_user_id = ?
        """,
        (interview_id, session["user_id"]),
    ).fetchone()

    if not interview:
        database_connection.close()
        if session.get("user_role") == ROLE_INTERVIEWER:
            return redirect(url_for("my_interviews_page"))
        return redirect(url_for("recruiter_applications_page"))

    aspects = database_connection.execute(
        """
        SELECT id, aspect_title, aspect_description, min_score, max_score, is_required, sort_order
        FROM template_aspects
        WHERE template_version_id = ?
        ORDER BY sort_order ASC, id ASC
        """,
        (interview["template_version_id"],),
    ).fetchall()

    existing_evaluation = database_connection.execute(
        """
        SELECT id, evaluation_status, overall_comment
        FROM evaluations
        WHERE interview_id = ? AND interviewer_user_id = ?
        """,
        (interview_id, session["user_id"]),
    ).fetchone()

    existing_scores: Dict[int, Dict[str, Any]] = {}
    if existing_evaluation:
        rows = database_connection.execute(
            "SELECT template_aspect_id, score, comment FROM evaluation_scores WHERE evaluation_id = ?",
            (existing_evaluation["id"],),
        ).fetchall()
        existing_scores = {
            row["template_aspect_id"]: {"score": row["score"], "comment": row["comment"]}
            for row in rows
        }

    if request.method == "POST":
        action = (request.form.get("action") or "submit").strip()  # save_draft | submit
        overall_comment = request.form.get("overall_comment", "").strip()

        if existing_evaluation and (existing_evaluation["evaluation_status"] or "") == "submitted":
            database_connection.close()
            flash("Deze evaluatie is al ingediend en kan niet meer aangepast worden.")
            if session.get("user_role") == ROLE_INTERVIEWER:
                return redirect(url_for("my_interviews_page"))
            return redirect(url_for("recruiter_applications_page"))

        if action == "submit":
            missing_required = []
            for aspect in aspects:
                if int(aspect["is_required"]) == 1:
                    field_name = f"score_{aspect['id']}"
                    if not request.form.get(field_name):
                        missing_required.append(aspect["aspect_title"])

            if missing_required:
                database_connection.close()
                flash("Please score all required criteria: " + ", ".join(missing_required))
                return redirect(url_for("evaluate_page", interview_id=interview_id))

        cursor = database_connection.cursor()
        new_status = "draft" if action == "save_draft" else "submitted"

        if existing_evaluation:
            evaluation_id = existing_evaluation["id"]
            cursor.execute(
                """
                UPDATE evaluations
                SET overall_comment = ?,
                    evaluation_status = ?,
                    updated_at = CURRENT_TIMESTAMP,
                    submitted_at = CASE
                        WHEN ? = 'submitted' THEN COALESCE(submitted_at, CURRENT_TIMESTAMP)
                        ELSE submitted_at
                    END
                WHERE id = ?
                """,
                (overall_comment if overall_comment else None, new_status, new_status, evaluation_id),
            )
        else:
            cursor.execute(
                """
                INSERT INTO evaluations (
                    interview_id, interviewer_user_id, template_version_id,
                    evaluation_status, overall_comment, created_at, submitted_at
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP,
                        CASE WHEN ? = 'submitted' THEN CURRENT_TIMESTAMP ELSE NULL END)
                """,
                (
                    interview_id,
                    session["user_id"],
                    interview["template_version_id"],
                    new_status,
                    overall_comment if overall_comment else None,
                    new_status,
                ),
            )
            evaluation_id = cursor.lastrowid

        for aspect in aspects:
            score_field = f"score_{aspect['id']}"
            comment_field = f"comment_{aspect['id']}"

            score_value = (request.form.get(score_field) or "").strip()
            comment_value = (request.form.get(comment_field) or "").strip()

            if not score_value:
                continue

            try:
                score_int = int(score_value)
            except ValueError:
                continue

            min_score = int(aspect["min_score"])
            max_score = int(aspect["max_score"])
            if score_int < min_score or score_int > max_score:
                continue

            cursor.execute(
                """
                INSERT INTO evaluation_scores (evaluation_id, template_aspect_id, score, comment)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(evaluation_id, template_aspect_id)
                DO UPDATE SET score = excluded.score, comment = excluded.comment
                """,
                (evaluation_id, aspect["id"], score_int, comment_value if comment_value else None),
            )

        if new_status == "submitted":
            database_connection.execute(
                """
                UPDATE interviews
                SET status = 'completed',
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (interview_id,),
            )

            log_audit_event(
                database_connection,
                event_type="evaluation_submitted",
                entity_type="evaluation",
                entity_id=evaluation_id,
                details={"interview_id": interview_id},
                performed_by_user_id=session["user_id"],
            )
            flash("Evaluatie ingediend!")
        else:
            log_audit_event(
                database_connection,
                event_type="evaluation_saved_draft",
                entity_type="evaluation",
                entity_id=evaluation_id,
                details={"interview_id": interview_id},
                performed_by_user_id=session["user_id"],
            )
            flash("Concept opgeslagen.")

        database_connection.commit()
        database_connection.close()

        if session.get("user_role") == ROLE_INTERVIEWER:
            return redirect(url_for("my_interviews_page"))
        return redirect(url_for("recruiter_applications_page"))

    database_connection.close()

    return render_template(
        "evaluate.html",
        aspects=aspects,
        candidate_name=interview["candidate_name"],
        candidate_email=interview["candidate_email"],
        vacancy_title=interview["vacancy_title"],
        phase_name=interview["phase_name"],
        cv_path=interview["cv_path"],
        interview_id=interview_id,
        existing_scores=existing_scores,
        existing_comment=existing_evaluation["overall_comment"] if existing_evaluation else "",
    )


@app.route("/recruiter/evaluations/<int:evaluation_id>/reopen", methods=["POST"])
def reopen_evaluation_action(evaluation_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    reason = (request.form.get("reopen_reason") or "").strip()
    if not reason:
        flash("Reden is verplicht om een evaluatie te heropenen.")
        return redirect(request.referrer or url_for("recruiter_applications_page"))

    database_connection = get_database_connection()

    evaluation = database_connection.execute(
        "SELECT id, interview_id, evaluation_status FROM evaluations WHERE id = ?",
        (evaluation_id,),
    ).fetchone()

    if not evaluation:
        database_connection.close()
        flash("Evaluatie niet gevonden.")
        return redirect(request.referrer or url_for("recruiter_applications_page"))

    if (evaluation["evaluation_status"] or "") != "submitted":
        database_connection.close()
        flash("Enkel ingediende (submitted) evaluaties kunnen heropend worden.")
        return redirect(request.referrer or url_for("recruiter_applications_page"))

    app_row = database_connection.execute(
        "SELECT application_id FROM interviews WHERE id = ?",
        (evaluation["interview_id"],),
    ).fetchone()
    application_id = int(app_row["application_id"]) if app_row else None

    database_connection.execute(
        """
        UPDATE evaluations
        SET evaluation_status = 'draft',
            submitted_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (evaluation_id,),
    )

    log_audit_event(
        database_connection,
        event_type="evaluation_reopened",
        entity_type="evaluation",
        entity_id=evaluation_id,
        details={"reason": reason, "interview_id": int(evaluation["interview_id"])},
        performed_by_user_id=session.get("user_id"),
    )

    database_connection.commit()
    database_connection.close()

    flash("Evaluatie heropend. Interviewer kan opnieuw aanpassen en indienen.")
    if application_id:
        return redirect(url_for("decision_page", application_id=application_id))
    return redirect(url_for("recruiter_applications_page"))


@app.route("/besluit/<int:application_id>", methods=["GET", "POST"])
def decision_page(application_id: int):
    if not require_any_role([ROLE_MANAGER, ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    application = database_connection.execute(
        """
        SELECT
            a.id,
            a.status AS app_status,
            c.full_name AS candidate_name,
            c.email_address AS candidate_email,
            a.resume_storage_filename AS cv_path,
            v.title AS vacancy_title,
            v.manager_id AS manager_id
        FROM applications a
        JOIN candidates c ON a.candidate_id = c.id
        JOIN vacancies v ON a.vacancy_id = v.id
        WHERE a.id = ?
        """,
        (application_id,),
    ).fetchone()

    if not application:
        database_connection.close()
        flash("Application not found.")
        return redirect(url_for("recruiter_applications_page"))

    user_role = session.get("user_role")
    user_id = session.get("user_id")

    is_owner_manager = (user_role == ROLE_MANAGER) and (int(application["manager_id"]) == int(user_id))
    can_make_decision = is_owner_manager

    if user_role == ROLE_MANAGER and not is_owner_manager:
        database_connection.close()
        flash("You do not have access to this application.")
        return redirect(url_for("manager_job_postings_page"))

    if request.method == "POST":
        if not can_make_decision:
            database_connection.close()
            flash("Alleen de Hiring Manager kan de eindbeslissing nemen.")
            return redirect(url_for("decision_page", application_id=application_id))

        desired_status = (request.form.get("decision_status") or "").strip()
        allowed_decisions = [APP_STATUS_REJECTED, APP_STATUS_HIRED]
        new_status = get_safe_choice(desired_status, allowed_decisions, application["app_status"])

        old_status = application["app_status"]

        if old_status in FINAL_APPLICATION_STATUSES:
            database_connection.close()
            flash("This application is already final and cannot be changed.")
            return redirect(url_for("decision_page", application_id=application_id))

        database_connection.execute(
            """
            UPDATE applications
            SET status = ?,
                status_updated_at = CURRENT_TIMESTAMP,
                status_updated_by_user_id = ?,
                status_updated_by_candidate_id = NULL
            WHERE id = ?
            """,
            (new_status, session["user_id"], application_id),
        )

        log_audit_event(
            database_connection,
            event_type="application_status_changed",
            entity_type="application",
            entity_id=application_id,
            from_status=old_status,
            to_status=new_status,
            performed_by_user_id=session["user_id"],
        )

        database_connection.commit()
        database_connection.close()

        flash(f"Candidate marked as: {APP_STATUS_LABELS.get(new_status, new_status)}")
        return redirect(url_for("decision_page", application_id=application_id))

    evaluations = database_connection.execute(
        """
        SELECT
            e.id,
            e.overall_comment,
            e.submitted_at,
            e.evaluation_status,
            COALESCE(u.full_name, u.email_address) AS interviewer_name,
            u.email_address AS interviewer_email
        FROM interviews i
        JOIN evaluations e ON e.interview_id = i.id
        JOIN users u ON e.interviewer_user_id = u.id
        WHERE i.application_id = ? AND e.evaluation_status = 'submitted'
        ORDER BY e.submitted_at DESC
        """,
        (application_id,),
    ).fetchall()

    scores_by_evaluation: Dict[int, List[Dict[str, Any]]] = {}
    totals_by_evaluation: Dict[int, Dict[str, Any]] = {}

    if evaluations:
        evaluation_ids = [int(e["id"]) for e in evaluations]
        placeholders = ",".join(["?"] * len(evaluation_ids))

        for eid in evaluation_ids:
            totals_by_evaluation[eid] = {"total": 0, "max": 0, "percent": None}

        score_rows = database_connection.execute(
            f"""
            SELECT
                es.evaluation_id,
                ta.aspect_title,
                ta.max_score,
                es.score,
                es.comment
            FROM evaluation_scores es
            JOIN template_aspects ta ON ta.id = es.template_aspect_id
            WHERE es.evaluation_id IN ({placeholders})
            ORDER BY es.evaluation_id DESC, ta.sort_order ASC, ta.id ASC
            """,
            tuple(evaluation_ids),
        ).fetchall()

        for row in score_rows:
            eval_id = int(row["evaluation_id"])

            scores_by_evaluation.setdefault(eval_id, []).append(
                {
                    "aspect_title": row["aspect_title"],
                    "score": int(row["score"] or 0),
                    "max_score": int(row["max_score"] or 0),
                    "comment": row["comment"],
                }
            )

            totals_by_evaluation[eval_id]["total"] += int(row["score"] or 0)
            totals_by_evaluation[eval_id]["max"] += int(row["max_score"] or 0)

        for eid, t in totals_by_evaluation.items():
            if t["max"] > 0:
                t["percent"] = round((t["total"] / t["max"]) * 100)

    database_connection.close()

    return render_template(
        "decision.html",
        application=application,
        evaluations=evaluations,
        scores_by_evaluation=scores_by_evaluation,
        totals_by_evaluation=totals_by_evaluation,
        status_labels=APP_STATUS_LABELS,
        can_make_decision=can_make_decision,
    )



# ============================================================
# 7) Templates: groups, versions, aspects
# ============================================================

@app.route("/recruiter/templates")
def templates_manage_page():
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    template_groups = database_connection.execute(
        """
        SELECT
            tg.id,
            tg.template_name AS group_name,
            tg.created_at AS created_at,
            COALESCE(
                (SELECT MAX(tv.created_at) FROM template_versions tv WHERE tv.template_group_id = tg.id),
                tg.created_at
            ) AS updated_at,
            (
                SELECT tv.version_number
                FROM template_versions tv
                WHERE tv.template_group_id = tg.id AND tv.status = 'published'
                ORDER BY tv.published_at DESC, tv.version_number DESC
                LIMIT 1
            ) AS published_version_number
        FROM template_groups tg
        ORDER BY tg.template_name ASC
        """
    ).fetchall()

    database_connection.close()

    return render_template("templates_manage.html", template_groups=template_groups)


@app.route("/recruiter/templates/create", methods=["POST"])
def create_template_group_action():
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    group_name = request.form.get("group_name", "").strip()
    if not group_name:
        flash("Geef een naam op voor de templategroep.")
        return redirect(url_for("templates_manage_page"))

    database_connection = get_database_connection()
    try:
        database_connection.execute(
            """
            INSERT INTO template_groups (template_name, template_description, created_by_user_id, created_at)
            VALUES (?, NULL, ?, CURRENT_TIMESTAMP)
            """,
            (group_name, session["user_id"]),
        )
        database_connection.commit()
        flash("Templategroep aangemaakt.")
    except sqlite3.IntegrityError:
        flash("Deze templategroep bestaat al (naam moet uniek zijn).")
    finally:
        database_connection.close()

    return redirect(url_for("templates_manage_page"))


@app.route("/recruiter/templates/<int:group_id>/delete", methods=["POST"])
def delete_template_group_action(group_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    group = database_connection.execute(
        "SELECT id, template_name FROM template_groups WHERE id = ?",
        (group_id,),
    ).fetchone()

    if not group:
        database_connection.close()
        flash("Templategroep niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    has_versions = database_connection.execute(
        "SELECT 1 FROM template_versions WHERE template_group_id = ? LIMIT 1",
        (group_id,),
    ).fetchone()

    if has_versions:
        database_connection.close()
        flash("Je kan deze templategroep niet verwijderen: er bestaan nog versies. Verwijder eerst de versies (of archiveer ze).")
        return redirect(url_for("templates_manage_page"))

    database_connection.execute("DELETE FROM template_groups WHERE id = ?", (group_id,))
    database_connection.commit()
    database_connection.close()

    flash("Templategroep verwijderd.")
    return redirect(url_for("templates_manage_page"))


@app.route("/recruiter/templates/<int:group_id>")
def template_group_detail_page(group_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    group = database_connection.execute(
        """
        SELECT id, template_name AS group_name, created_at
        FROM template_groups
        WHERE id = ?
        """,
        (group_id,),
    ).fetchone()

    if not group:
        database_connection.close()
        flash("Templategroep niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    versions = database_connection.execute(
        """
        SELECT id, template_group_id, version_number, version_label, status, created_at, published_at
        FROM template_versions
        WHERE template_group_id = ?
        ORDER BY version_number DESC
        """,
        (group_id,),
    ).fetchall()

    published_version = database_connection.execute(
        """
        SELECT id, template_group_id, version_number, version_label, status, created_at, published_at
        FROM template_versions
        WHERE template_group_id = ? AND status = 'published'
        ORDER BY published_at DESC, version_number DESC
        LIMIT 1
        """,
        (group_id,),
    ).fetchone()

    database_connection.close()

    return render_template(
        "template_group_detail.html",
        group=group,
        versions=versions,
        published_version=published_version,
    )


@app.route("/recruiter/templates/<int:group_id>/versions/create", methods=["POST"])
def create_template_version_action(group_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    group = database_connection.execute("SELECT id FROM template_groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        database_connection.close()
        flash("Templategroep niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    next_version_row = database_connection.execute(
        """
        SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
        FROM template_versions
        WHERE template_group_id = ?
        """,
        (group_id,),
    ).fetchone()

    next_version_number = int(next_version_row["next_version"]) if next_version_row else 1

    cursor = database_connection.cursor()
    cursor.execute(
        """
        INSERT INTO template_versions (
            template_group_id, version_number, version_label, status, created_by_user_id, created_at
        )
        VALUES (?, ?, NULL, 'draft', ?, CURRENT_TIMESTAMP)
        """,
        (group_id, next_version_number, session["user_id"]),
    )
    version_id = cursor.lastrowid

    database_connection.commit()
    database_connection.close()

    flash(f"Nieuwe versie v{next_version_number} aangemaakt.")
    return redirect(url_for("template_version_edit_page", version_id=version_id))


@app.route("/recruiter/template-versions/<int:version_id>")
def template_version_edit_page(version_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    version = database_connection.execute(
        """
        SELECT id, template_group_id, version_number, version_label, status, created_at, published_at
        FROM template_versions
        WHERE id = ?
        """,
        (version_id,),
    ).fetchone()

    if not version:
        database_connection.close()
        flash("Templateversie niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    group = database_connection.execute(
        """
        SELECT id, template_name AS group_name, created_at
        FROM template_groups
        WHERE id = ?
        """,
        (version["template_group_id"],),
    ).fetchone()

    aspects = database_connection.execute(
        """
        SELECT id, template_version_id, aspect_title, aspect_description, min_score, max_score, is_required, sort_order
        FROM template_aspects
        WHERE template_version_id = ?
        ORDER BY sort_order ASC, id ASC
        """,
        (version_id,),
    ).fetchall()

    database_connection.close()

    return render_template("template_version_edit.html", group=group, version=version, aspects=aspects)


@app.route("/recruiter/template-versions/<int:version_id>/update", methods=["POST"])
def template_version_update_action(version_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    version_label = request.form.get("version_label", "").strip() or None

    database_connection = get_database_connection()

    version = database_connection.execute(
        "SELECT id, status FROM template_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if not version:
        database_connection.close()
        flash("Templateversie niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    database_connection.execute(
        """
        UPDATE template_versions
        SET version_label = ?
        WHERE id = ?
        """,
        (version_label, version_id),
    )
    database_connection.commit()
    database_connection.close()

    flash("Versie opgeslagen.")
    return redirect(url_for("template_version_edit_page", version_id=version_id))


@app.route("/recruiter/template-versions/<int:version_id>/publish", methods=["POST"])
def publish_template_version_action(version_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    version = database_connection.execute(
        """
        SELECT id, template_group_id, version_number, status
        FROM template_versions
        WHERE id = ?
        """,
        (version_id,),
    ).fetchone()

    if not version:
        database_connection.close()
        flash("Templateversie niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    aspect_count = database_connection.execute(
        "SELECT COUNT(*) AS cnt FROM template_aspects WHERE template_version_id = ?",
        (version_id,),
    ).fetchone()
    if not aspect_count or int(aspect_count["cnt"]) < 3:
        database_connection.close()
        flash("Je kan niet publiceren zonder minstens 3 criteria/aspects.")
        return redirect(url_for("template_version_edit_page", version_id=version_id))

    database_connection.execute(
        """
        UPDATE template_versions
        SET status = 'archived'
        WHERE template_group_id = ? AND status = 'published'
        """,
        (version["template_group_id"],),
    )

    database_connection.execute(
        """
        UPDATE template_versions
        SET status = 'published',
            published_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (version_id,),
    )

    database_connection.commit()
    database_connection.close()

    flash(f"Versie v{version['version_number']} is nu gepubliceerd.")
    return redirect(url_for("template_group_detail_page", group_id=version["template_group_id"]))


@app.route("/recruiter/template-versions/<int:version_id>/delete", methods=["POST"])
def delete_template_version_action(version_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    version = database_connection.execute(
        """
        SELECT id, template_group_id, version_number, status
        FROM template_versions
        WHERE id = ?
        """,
        (version_id,),
    ).fetchone()

    if not version:
        database_connection.close()
        flash("Templateversie niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    if (version["status"] or "") == "published":
        database_connection.close()
        flash("Je kan een published versie niet verwijderen. Maak eerst een andere versie published (dan wordt deze archived).")
        return redirect(url_for("template_group_detail_page", group_id=version["template_group_id"]))

    linked_phase = database_connection.execute(
        "SELECT 1 FROM interview_phases WHERE template_version_id = ? LIMIT 1",
        (version_id,),
    ).fetchone()
    if linked_phase:
        database_connection.close()
        flash("Je kan deze versie niet verwijderen: ze is gekoppeld aan één of meer interviewfases.")
        return redirect(url_for("template_group_detail_page", group_id=version["template_group_id"]))

    used_eval = database_connection.execute(
        "SELECT 1 FROM evaluations WHERE template_version_id = ? LIMIT 1",
        (version_id,),
    ).fetchone()
    if used_eval:
        database_connection.close()
        flash("Je kan deze versie niet verwijderen: ze is al gebruikt in evaluaties.")
        return redirect(url_for("template_group_detail_page", group_id=version["template_group_id"]))

    database_connection.execute("DELETE FROM template_aspects WHERE template_version_id = ?", (version_id,))
    database_connection.execute("DELETE FROM template_versions WHERE id = ?", (version_id,))

    database_connection.commit()
    database_connection.close()

    flash(f"Templateversie v{version['version_number']} verwijderd.")
    return redirect(url_for("template_group_detail_page", group_id=version["template_group_id"]))


@app.route("/recruiter/template-versions/<int:version_id>/aspects/create", methods=["POST"])
def create_template_aspect_action(version_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    aspect_title = request.form.get("aspect_title", "").strip()
    aspect_description = request.form.get("aspect_description", "").strip() or None

    try:
        min_score = int(request.form.get("min_score", "1"))
        max_score = int(request.form.get("max_score", "5"))
        sort_raw = (request.form.get("sort_order") or "").strip()
        sort_order = int(sort_raw) if sort_raw else 10
    except ValueError:
        flash("Scores/volgorde moeten numeriek zijn.")
        return redirect(url_for("template_version_edit_page", version_id=version_id))

    is_required = 1 if request.form.get("is_required") == "1" else 0

    if not aspect_title:
        flash("Titel is verplicht.")
        return redirect(url_for("template_version_edit_page", version_id=version_id))

    if max_score < min_score:
        flash("Max score moet groter of gelijk zijn aan min score.")
        return redirect(url_for("template_version_edit_page", version_id=version_id))

    if sort_order <= 0:
        flash("Volgorde moet groter zijn dan 0.")
        return redirect(url_for("template_version_edit_page", version_id=version_id))

    database_connection = get_database_connection()

    version = database_connection.execute(
        "SELECT id FROM template_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if not version:
        database_connection.close()
        flash("Templateversie niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    database_connection.execute(
        """
        INSERT INTO template_aspects (
            template_version_id,
            aspect_title,
            aspect_description,
            weight,
            min_score,
            max_score,
            is_required,
            sort_order
        )
        VALUES (?, ?, ?, 1.0, ?, ?, ?, ?)
        """,
        (version_id, aspect_title, aspect_description, min_score, max_score, is_required, sort_order),
    )

    database_connection.commit()
    database_connection.close()

    flash("Criterium toegevoegd.")
    return redirect(url_for("template_version_edit_page", version_id=version_id))


@app.route("/recruiter/template-aspects/<int:aspect_id>/update", methods=["POST"])
def update_template_aspect_action(aspect_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    aspect_title = request.form.get("aspect_title", "").strip()
    aspect_description = request.form.get("aspect_description", "").strip() or None

    try:
        min_score = int(request.form.get("min_score", "1"))
        max_score = int(request.form.get("max_score", "5"))
        sort_raw = (request.form.get("sort_order") or "").strip()
        sort_order = int(sort_raw) if sort_raw else 10
    except ValueError:
        flash("Scores/volgorde moeten numeriek zijn.")
        return redirect(url_for("templates_manage_page"))

    is_required = 1 if request.form.get("is_required") == "1" else 0

    if not aspect_title:
        flash("Titel is verplicht.")
        return redirect(url_for("templates_manage_page"))

    if max_score < min_score:
        flash("Max score moet groter of gelijk zijn aan min score.")
        return redirect(url_for("templates_manage_page"))

    if sort_order <= 0:
        flash("Volgorde moet groter zijn dan 0.")
        return redirect(url_for("templates_manage_page"))

    database_connection = get_database_connection()

    existing = database_connection.execute(
        "SELECT template_version_id FROM template_aspects WHERE id = ?",
        (aspect_id,),
    ).fetchone()
    if not existing:
        database_connection.close()
        flash("Criterium niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    database_connection.execute(
        """
        UPDATE template_aspects
        SET aspect_title = ?,
            aspect_description = ?,
            min_score = ?,
            max_score = ?,
            is_required = ?,
            sort_order = ?
        WHERE id = ?
        """,
        (aspect_title, aspect_description, min_score, max_score, is_required, sort_order, aspect_id),
    )

    database_connection.commit()
    database_connection.close()

    flash("Criterium opgeslagen.")
    return redirect(url_for("template_version_edit_page", version_id=existing["template_version_id"]))


@app.route("/recruiter/template-aspects/<int:aspect_id>/delete", methods=["POST"])
def delete_template_aspect_action(aspect_id: int):
    if not require_any_role([ROLE_RECRUITER, ROLE_ADMIN]):
        return redirect(url_for("dashboard_page"))

    database_connection = get_database_connection()

    existing = database_connection.execute(
        "SELECT template_version_id FROM template_aspects WHERE id = ?",
        (aspect_id,),
    ).fetchone()
    if not existing:
        database_connection.close()
        flash("Criterium niet gevonden.")
        return redirect(url_for("templates_manage_page"))

    database_connection.execute("DELETE FROM template_aspects WHERE id = ?", (aspect_id,))
    database_connection.commit()
    database_connection.close()

    flash("Criterium verwijderd.")
    return redirect(url_for("template_version_edit_page", version_id=existing["template_version_id"]))



# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug)