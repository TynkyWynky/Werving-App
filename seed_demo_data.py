from __future__ import annotations

import argparse
import os
import random
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

from werkzeug.security import generate_password_hash

# ----------------------------
# Config
# ----------------------------
DEFAULT_PASSWORD = "Password123!"

ROLES = {
    "manager": "manager",
    "recruiter": "recruiter",
    "interviewer": "interviewer",
    "admin": "admin",
}

JOB_STATUSES = ["draft", "pending_review", "changes_requested", "published", "closed"]
APP_STATUSES = ["new", "in_review", "shortlisted", "interview", "rejected", "offered", "hired", "withdrawn"]


def now_sql() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def days_from_now(days: int, hour: int = 10, minute: int = 0) -> str:
    dt = datetime.utcnow() + timedelta(days=days)
    dt = dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def create_dummy_pdf(path: Path, title: str) -> None:
    """
    Minimal-ish PDF content (enough to download/open in many viewers).
    """
    # Tiny valid PDF (not fancy)
    content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 120 >>
stream
BT
/F1 18 Tf
72 760 Td
({title}) Tj
/F1 12 Tf
72 730 Td
(Demo CV - dummy file) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000060 00000 n
0000000117 00000 n
0000000276 00000 n
0000000449 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
520
%%EOF
"""
    path.write_bytes(content.encode("utf-8"))


def reset_tables(conn: sqlite3.Connection) -> None:
    """
    Delete in a safe order because of FK constraints.
    """
    tables_in_order = [
        "evaluation_scores",
        "evaluations",
        "interview_interviewers",
        "interviews",
        "phase_interviewers",
        "interview_phases",
        "applications",
        "template_aspects",
        "template_versions",
        "template_groups",
        "notifications",
        "audit_log",
        "vacancies",
        "candidates",
        "users",
    ]
    for t in tables_in_order:
        conn.execute(f"DELETE FROM {t};")
    conn.commit()


def insert_user(conn: sqlite3.Connection, email: str, role: str, full_name: str) -> int:
    pw_hash = generate_password_hash(DEFAULT_PASSWORD)
    cur = conn.execute(
        """
        INSERT INTO users (email_address, password_hash, full_name, user_role, is_active)
        VALUES (?, ?, ?, ?, 1)
        """,
        (email.lower(), pw_hash, full_name, role),
    )
    return int(cur.lastrowid)


def insert_candidate(conn: sqlite3.Connection, email: str, name: str, with_password: bool = True) -> int:
    pw_hash = generate_password_hash(DEFAULT_PASSWORD) if with_password else None
    cur = conn.execute(
        """
        INSERT INTO candidates (email_address, password_hash, full_name, phone_number, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (email.lower(), pw_hash, name, f"+32 4{random.randint(70, 99)} {random.randint(100, 999)} {random.randint(100, 999)}"),
    )
    return int(cur.lastrowid)


def insert_template_bundle(
    conn: sqlite3.Connection,
    created_by_user_id: int,
    group_name: str,
    version_label: str,
    aspects: List[Tuple[str, str]],
) -> Tuple[int, int, List[int]]:
    """
    Returns: (group_id, version_id, aspect_ids)
    Creates a group + a published version + aspects
    """
    cur = conn.execute(
        """
        INSERT INTO template_groups (template_name, template_description, created_by_user_id)
        VALUES (?, ?, ?)
        """,
        (group_name, f"Demo template: {group_name}", created_by_user_id),
    )
    group_id = int(cur.lastrowid)

    cur = conn.execute(
        """
        INSERT INTO template_versions (template_group_id, version_number, version_label, status, created_by_user_id, published_at)
        VALUES (?, 1, ?, 'published', ?, CURRENT_TIMESTAMP)
        """,
        (group_id, version_label, created_by_user_id),
    )
    version_id = int(cur.lastrowid)

    aspect_ids: List[int] = []
    for idx, (title, desc) in enumerate(aspects, start=1):
        cur = conn.execute(
            """
            INSERT INTO template_aspects (
                template_version_id, aspect_title, aspect_description, weight,
                min_score, max_score, is_required, sort_order
            )
            VALUES (?, ?, ?, 1.0, 1, 5, 1, ?)
            """,
            (version_id, title, desc, idx * 10),
        )
        aspect_ids.append(int(cur.lastrowid))

    return group_id, version_id, aspect_ids


def insert_vacancy(
    conn: sqlite3.Connection,
    manager_id: int,
    title: str,
    department: str,
    description: str,
    status: str,
    reviewed_by_user_id: int | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO vacancies (
            title, department, description,
            location, employment_type, experience_level,
            manager_id, status,
            submitted_at, reviewed_by_user_id, reviewed_at, published_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            title,
            department,
            description,
            "Brussels",
            "full-time",
            "junior",
            manager_id,
            status,
            now_sql() if status in ("pending_review", "published") else None,
            reviewed_by_user_id if status in ("published", "changes_requested") else None,
            now_sql() if status in ("published", "changes_requested") else None,
            now_sql() if status == "published" else None,
        ),
    )
    return int(cur.lastrowid)


def insert_phase(conn: sqlite3.Connection, vacancy_id: int, name: str, seq: int, template_version_id: int, is_active: int = 1) -> int:
    cur = conn.execute(
        """
        INSERT INTO interview_phases (vacancy_id, phase_name, sequence_number, template_version_id, is_active)
        VALUES (?, ?, ?, ?, ?)
        """,
        (vacancy_id, name, seq, template_version_id, is_active),
    )
    return int(cur.lastrowid)


def assign_phase_interviewers(conn: sqlite3.Connection, phase_id: int, interviewer_ids: List[int]) -> None:
    for iid in interviewer_ids:
        conn.execute(
            """
            INSERT OR IGNORE INTO phase_interviewers (phase_id, interviewer_user_id)
            VALUES (?, ?)
            """,
            (phase_id, iid),
        )


def insert_application(
    conn: sqlite3.Connection,
    vacancy_id: int,
    candidate_id: int,
    status: str,
    resume_storage_filename: str | None,
    cover_letter: str,
) -> int:
    token = secrets.token_urlsafe(24)
    cur = conn.execute(
        """
        INSERT INTO applications (
            vacancy_id, candidate_id, status,
            applied_at,
            gdpr_consent, gdpr_consent_at,
            status_updated_at, status_updated_by_candidate_id,
            cover_letter,
            resume_original_filename, resume_storage_filename,
            status_view_token
        )
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
        """,
        (
            vacancy_id,
            candidate_id,
            status,
            candidate_id,
            cover_letter,
            "cv.pdf" if resume_storage_filename else None,
            resume_storage_filename,
            token,
        ),
    )
    return int(cur.lastrowid)


def insert_interview(
    conn: sqlite3.Connection,
    application_id: int,
    phase_id: int,
    scheduled_start: str,
    status: str,
    created_by_user_id: int,
    meeting_link: str | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO interviews (
            application_id, phase_id,
            scheduled_start, scheduled_end,
            location, meeting_link,
            status, created_by_user_id, created_at,
            completed_at, notes
        )
        VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, CURRENT_TIMESTAMP,
                CASE WHEN ? = 'completed' THEN CURRENT_TIMESTAMP ELSE NULL END,
                ?)
        """,
        (
            application_id,
            phase_id,
            scheduled_start,
            meeting_link,
            status,
            created_by_user_id,
            status,
            "Demo interview notes",
        ),
    )
    return int(cur.lastrowid)


def insert_interview_interviewers(conn: sqlite3.Connection, interview_id: int, interviewer_ids: List[int]) -> None:
    # first = primary, rest = panel
    for idx, iid in enumerate(interviewer_ids):
        role = "primary" if idx == 0 else "panel"
        conn.execute(
            """
            INSERT OR IGNORE INTO interview_interviewers (interview_id, interviewer_user_id, interviewer_role)
            VALUES (?, ?, ?)
            """,
            (interview_id, iid, role),
        )


def insert_evaluation_with_scores(
    conn: sqlite3.Connection,
    interview_id: int,
    interviewer_user_id: int,
    template_version_id: int,
    aspect_ids: List[int],
    status: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO evaluations (
            interview_id, interviewer_user_id, template_version_id,
            evaluation_status, overall_comment, created_at, updated_at, submitted_at
        )
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                CASE WHEN ? = 'submitted' THEN CURRENT_TIMESTAMP ELSE NULL END)
        """,
        (
            interview_id,
            interviewer_user_id,
            template_version_id,
            status,
            "Sterke kandidaat, goede communicatie." if status == "submitted" else "Nog bezig met evaluatie...",
            status,
        ),
    )
    evaluation_id = int(cur.lastrowid)

    for aid in aspect_ids:
        score = random.randint(2, 5) if status == "submitted" else random.randint(1, 4)
        conn.execute(
            """
            INSERT INTO evaluation_scores (evaluation_id, template_aspect_id, score, comment)
            VALUES (?, ?, ?, ?)
            """,
            (
                evaluation_id,
                aid,
                score,
                "OK" if score >= 3 else "Kan beter",
            ),
        )

    return evaluation_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="Delete existing data first")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent  # werving_app/
    db_path = Path(os.environ.get("SQLITE_DB_PATH", str(base_dir / "database.db")))

    uploads_dir = base_dir / "uploads"
    uploads_dir.mkdir(exist_ok=True)

    conn = connect(db_path)

    if args.reset:
        reset_tables(conn)

    # ----------------------------
    # Users
    # ----------------------------
    manager_id = insert_user(conn, "manager@bedrijf.be", ROLES["manager"], "Hoi, Manager")
    recruiter_id = insert_user(conn, "recruiter@bedrijf.be", ROLES["recruiter"], "Hoi, Recruiter")
    admin_id = insert_user(conn, "admin@bedrijf.be", ROLES["admin"], "Admin User")

    interviewer_ids = []
    for i in range(1, 6):
        interviewer_ids.append(
            insert_user(conn, f"interviewer{i}@bedrijf.be", ROLES["interviewer"], f"Interviewer {i}")
        )

    # ----------------------------
    # Templates (3 bundles, published)
    # ----------------------------
    screening_aspects = [
        ("Motivatie", "Is de motivatie duidelijk en relevant?"),
        ("Communicatie", "Kan de kandidaat helder communiceren?"),
        ("Beschikbaarheid", "Past de beschikbaarheid bij de planning?"),
        ("Basis fit", "Matcht de kandidaat met de vacature op hoofdlijnen?"),
    ]
    tech_aspects = [
        ("Technische kennis", "Begrip van basisconcepten en praktijk."),
        ("Probleemoplossend", "Aanpak en redenering bij challenges."),
        ("Code kwaliteit", "Leesbaarheid, structuur, best practices."),
        ("Tooling", "Kennis van relevante tools/stack."),
    ]
    culture_aspects = [
        ("Team fit", "Samenwerking en attitude."),
        ("Leren", "Leergierigheid en groeipotentieel."),
        ("Verantwoordelijkheid", "Ownership en betrouwbaarheid."),
        ("Stressbestendig", "Omgaan met deadlines en druk."),
    ]

    _, tv_screening, aspects_screening = insert_template_bundle(
        conn, recruiter_id, "Recruiter Screening", "v1 - Screening", screening_aspects
    )
    _, tv_tech, aspects_tech = insert_template_bundle(
        conn, recruiter_id, "Technical Interview", "v1 - Tech", tech_aspects
    )
    _, tv_culture, aspects_culture = insert_template_bundle(
        conn, recruiter_id, "Culture Fit", "v1 - Culture", culture_aspects
    )

    # ----------------------------
    # Vacancies
    # ----------------------------
    vac_pub_id = insert_vacancy(
        conn,
        manager_id=manager_id,
        title="Junior IT Support",
        department="IT",
        description="Support tickets, basic networking, Windows/Linux, user support.",
        status="published",
        reviewed_by_user_id=recruiter_id,
    )
    vac_pending_id = insert_vacancy(
        conn,
        manager_id=manager_id,
        title="Medior Python Developer",
        department="IT",
        description="APIs bouwen in Python, testing, CI/CD, SQL, code reviews.",
        status="pending_review",
        reviewed_by_user_id=None,
    )

    # ----------------------------
    # Interview phases (3 for published vacancy)
    # ----------------------------
    ph1 = insert_phase(conn, vac_pub_id, "Recruiter screening", 1, tv_screening, is_active=1)
    ph2 = insert_phase(conn, vac_pub_id, "Technical interview", 2, tv_tech, is_active=1)
    ph3 = insert_phase(conn, vac_pub_id, "Culture fit", 3, tv_culture, is_active=1)

    # Assign interviewers to phase 2 & 3 (manager responsibility)
    assign_phase_interviewers(conn, ph2, interviewer_ids[:3])
    assign_phase_interviewers(conn, ph3, interviewer_ids[2:5])

    # Also create phases for the pending vacancy (so recruiter can publish later)
    insert_phase(conn, vac_pending_id, "Recruiter screening", 1, tv_screening, is_active=1)
    insert_phase(conn, vac_pending_id, "Technical interview", 2, tv_tech, is_active=1)

    # ----------------------------
    # Candidates + Applications
    # ----------------------------
    candidate_ids: List[int] = []
    applications: List[Dict] = []

    candidate_names = [
        "Alex Peeters", "Sophie Janssens", "Mehmet Demir", "Laura Vermeulen",
        "Noah Dubois", "Emma De Smet", "Milan Van den Broeck", "Lina Ait Benali",
    ]

    for idx, name in enumerate(candidate_names, start=1):
        email = f"candidate{idx}@mail.com"
        with_pw = idx % 2 == 0  # half have password, half will be set-password flow later
        cid = insert_candidate(conn, email, name, with_password=with_pw)
        candidate_ids.append(cid)

        # Create a dummy CV file
        cv_filename = f"cv_candidate{idx}.pdf"
        create_dummy_pdf(uploads_dir / cv_filename, f"CV - {name}")

        # Spread statuses
        status = random.choice(["new", "in_review", "shortlisted", "interview"])
        app_id = insert_application(
            conn,
            vacancy_id=vac_pub_id,
            candidate_id=cid,
            status=status,
            resume_storage_filename=cv_filename,
            cover_letter="Ik ben gemotiveerd en wil graag starten in IT support.",
        )
        applications.append(
            {"application_id": app_id, "candidate_id": cid, "status": status}
        )

    # Add a couple more applications (for variety)
    for extra in range(1, 4):
        cid = random.choice(candidate_ids)
        cv_filename = f"cv_extra{extra}.pdf"
        create_dummy_pdf(uploads_dir / cv_filename, f"Extra CV {extra}")
        status = random.choice(["rejected", "withdrawn", "offered"])
        app_id = insert_application(
            conn,
            vacancy_id=vac_pub_id,
            candidate_id=cid,
            status=status,
            resume_storage_filename=cv_filename,
            cover_letter="Extra sollicitatie (demo).",
        )
        applications.append({"application_id": app_id, "candidate_id": cid, "status": status})

    # ----------------------------
    # Interviews + Evaluations
    # ----------------------------
    # Pick some apps in interview status and schedule phase 1 + phase 2
    interview_apps = [a for a in applications if a["status"] == "interview"]
    random.shuffle(interview_apps)

    # Ensure at least 3 have interview status for a strong demo
    if len(interview_apps) < 3:
        for a in applications[:3]:
            conn.execute(
                "UPDATE applications SET status = 'interview', status_updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (a["application_id"],),
            )
        interview_apps = [a for a in applications[:3]]

    # Create interviews
    for idx, a in enumerate(interview_apps[:4], start=1):
        app_id = a["application_id"]

        # Phase 1 planned by recruiter (auto interviewer = recruiter)
        i1 = insert_interview(
            conn,
            application_id=app_id,
            phase_id=ph1,
            scheduled_start=days_from_now(idx, hour=9 + idx),
            status="planned",
            created_by_user_id=recruiter_id,
            meeting_link="https://teams.microsoft.com/l/meetup-join/demo-phase1" if idx % 2 == 0 else None,
        )
        insert_interview_interviewers(conn, i1, [recruiter_id])

        # Phase 2: planned, multiple interviewers (manager assigned list)
        chosen = random.sample(interviewer_ids[:3], k=2)
        i2_status = "planned" if idx % 2 == 1 else "completed"
        i2 = insert_interview(
            conn,
            application_id=app_id,
            phase_id=ph2,
            scheduled_start=days_from_now(idx + 1, hour=11),
            status=i2_status,
            created_by_user_id=recruiter_id,
            meeting_link="https://teams.microsoft.com/l/meetup-join/demo-phase2",
        )
        insert_interview_interviewers(conn, i2, chosen)

        # Evaluations for completed interviews
        if i2_status == "completed":
            # First interviewer submitted, second draft (demo progress 1/2)
            insert_evaluation_with_scores(conn, i2, chosen[0], tv_tech, aspects_tech, status="submitted")
            insert_evaluation_with_scores(conn, i2, chosen[1], tv_tech, aspects_tech, status="draft")

    # Add one Phase 3 completed interview with 2 interviewers + all submitted (good “decision page” demo)
    special_app = interview_apps[0]["application_id"]
    chosen3 = random.sample(interviewer_ids[2:5], k=2)
    i3 = insert_interview(
        conn,
        application_id=special_app,
        phase_id=ph3,
        scheduled_start=days_from_now(5, hour=14),
        status="completed",
        created_by_user_id=recruiter_id,
        meeting_link="https://teams.microsoft.com/l/meetup-join/demo-phase3",
    )
    insert_interview_interviewers(conn, i3, chosen3)
    insert_evaluation_with_scores(conn, i3, chosen3[0], tv_culture, aspects_culture, status="submitted")
    insert_evaluation_with_scores(conn, i3, chosen3[1], tv_culture, aspects_culture, status="submitted")

    # ----------------------------
    # Notifications (optional)
    # ----------------------------
    conn.execute(
        """
        INSERT INTO notifications (recipient_type, recipient_id, channel, subject, body, delivery_status)
        VALUES ('user', ?, 'in_app', 'Demo notificatie', 'Welkom! Dit is nepdata voor je demo.', 'sent')
        """,
        (recruiter_id,),
    )

    conn.commit()
    conn.close()

    print("\n✅ Demo data seeded!")
    print("Login accounts (allemaal wachtwoord):", DEFAULT_PASSWORD)
    print(" - Manager: manager@bedrijf.be")
    print(" - Recruiter: recruiter@bedrijf.be")
    print(" - Admin: admin@bedrijf.be")
    print(" - Interviewers: interviewer1@bedrijf.be ... interviewer5@bedrijf.be")
    print("\nTip: ga als Recruiter naar Sollicitaties → plan interviews → bekijk Interviews pagina → evalueren.\n")


if __name__ == "__main__":
    main()
