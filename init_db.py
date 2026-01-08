import os
import sqlite3
from werkzeug.security import generate_password_hash


# -----------------------------
# Project paths (always absolute)
# -----------------------------
BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIRECTORY, "database.db")
SCHEMA_PATH = os.path.join(BASE_DIRECTORY, "schema.sql")


def initialize_database() -> None:
    """
    Rebuilds the SQLite database from schema.sql and seeds minimal, useful demo data.
    Password for seeded users is: admin
    """
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"Schema file not found at: {SCHEMA_PATH}")

    print("Rebuilding database...")
    database_connection = sqlite3.connect(DATABASE_PATH)

    try:
        # Ensure foreign keys are enforced at runtime (SQLite-specific)
        database_connection.execute("PRAGMA foreign_keys = ON;")

        with open(SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
            schema_sql = schema_file.read()
        database_connection.executescript(schema_sql)

        cursor = database_connection.cursor()

        # ------------------------------------------------------------
        # 1) Seed internal users (password: 'admin')
        # ------------------------------------------------------------
        print("Seeding internal users...")
        default_password_hash = generate_password_hash("admin")

        internal_users = [
            {
                "email_address": "recruiter@bedrijf.be",
                "password_hash": default_password_hash,
                "full_name": "Default Recruiter",
                "user_role": "recruiter",
            },
            {
                "email_address": "manager@bedrijf.be",
                "password_hash": default_password_hash,
                "full_name": "Default Manager",
                "user_role": "manager",
            },
            {
                "email_address": "interviewer@bedrijf.be",
                "password_hash": default_password_hash,
                "full_name": "Default Interviewer",
                "user_role": "interviewer",
            },
            {
                "email_address": "admin@bedrijf.be",
                "password_hash": default_password_hash,
                "full_name": "Default Admin",
                "user_role": "admin",
            },
        ]

        for user in internal_users:
            cursor.execute(
                """
                INSERT INTO users (email_address, password_hash, full_name, user_role, is_active)
                VALUES (?, ?, ?, ?, 1)
                """,
                (user["email_address"], user["password_hash"], user["full_name"], user["user_role"]),
            )

        # Fetch seeded user ids for later linking
        recruiter_user_id = cursor.execute(
            "SELECT id FROM users WHERE email_address = ?",
            ("recruiter@bedrijf.be",),
        ).fetchone()[0]

        manager_user_id = cursor.execute(
            "SELECT id FROM users WHERE email_address = ?",
            ("manager@bedrijf.be",),
        ).fetchone()[0]

        interviewer_user_id = cursor.execute(
            "SELECT id FROM users WHERE email_address = ?",
            ("interviewer@bedrijf.be",),
        ).fetchone()[0]

        # ------------------------------------------------------------
        # 2) Seed a candidate (external user)
        # ------------------------------------------------------------
        print("Seeding a demo candidate...")
        candidate_password_hash = generate_password_hash("admin")  # demo: same password for ease
        cursor.execute(
            """
            INSERT INTO candidates (email_address, password_hash, full_name, phone_number, is_active)
            VALUES (?, ?, ?, ?, 1)
            """,
            ("kandidaat@voorbeeld.be", candidate_password_hash, "Demo Candidate", "+32 470 00 00 00"),
        )
        candidate_id = cursor.lastrowid

        # ------------------------------------------------------------
        # 3) Seed a template group + version + aspects (UC-01 foundation)
        # ------------------------------------------------------------
        print("Seeding evaluation template (group + version + aspects)...")

        cursor.execute(
            """
            INSERT INTO template_groups (template_name, template_description, created_by_user_id)
            VALUES (?, ?, ?)
            """,
            ("Standard Interview Template", "Default interview evaluation template.", recruiter_user_id),
        )
        template_group_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO template_versions (
                template_group_id, version_number, version_label, status, created_by_user_id, published_at
            )
            VALUES (?, ?, ?, 'published', ?, CURRENT_TIMESTAMP)
            """,
            (template_group_id, 1, "v1 - Standard", recruiter_user_id),
        )
        template_version_id = cursor.lastrowid

        default_aspects = [
            {
                "aspect_title": "Communication",
                "aspect_description": "Clarity, structure, and listening skills.",
                "weight": 1.0,
                "sort_order": 1,
            },
            {
                "aspect_title": "Technical knowledge",
                "aspect_description": "Relevant technical understanding for the role.",
                "weight": 1.0,
                "sort_order": 2,
            },
            {
                "aspect_title": "Motivation",
                "aspect_description": "Interest in the position and willingness to learn.",
                "weight": 1.0,
                "sort_order": 3,
            },
            {
                "aspect_title": "Culture fit",
                "aspect_description": "Matches the team's values and ways of working.",
                "weight": 1.0,
                "sort_order": 4,
            },
        ]

        for aspect in default_aspects:
            cursor.execute(
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
                VALUES (?, ?, ?, ?, 1, 5, 1, ?)
                """,
                (
                    template_version_id,
                    aspect["aspect_title"],
                    aspect["aspect_description"],
                    aspect["weight"],
                    aspect["sort_order"],
                ),
            )

        # ------------------------------------------------------------
        # 4) Seed a demo vacancy + phases (foundation for phase-based interviews)
        # ------------------------------------------------------------
        print("Seeding a demo vacancy + interview phases...")

        cursor.execute(
            """
            INSERT INTO vacancies (
                title, department, description, location, employment_type, experience_level,
                manager_id, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'published', CURRENT_TIMESTAMP)
            """,
            (
                "Junior IT Support",
                "IT",
                "Support internal users, troubleshoot issues, and assist with day-to-day IT operations.",
                "Brussels",
                "Full-time",
                "Junior",
                manager_user_id,
            ),
        )
        vacancy_id = cursor.lastrowid

        # Minimal 2 phases for a realistic flow
        interview_phases = [
            {"phase_name": "Recruiter screening", "sequence_number": 1},
            {"phase_name": "Technical interview", "sequence_number": 2},
        ]

        for phase in interview_phases:
            cursor.execute(
                """
                INSERT INTO interview_phases (vacancy_id, phase_name, sequence_number, template_version_id, is_active)
                VALUES (?, ?, ?, ?, 1)
                """,
                (vacancy_id, phase["phase_name"], phase["sequence_number"], template_version_id),
            )

        # ------------------------------------------------------------
        # 5) Seed a demo application (candidate applied to vacancy)
        # ------------------------------------------------------------
        print("Seeding a demo application...")
        cursor.execute(
            """
            INSERT INTO applications (
                vacancy_id, candidate_id, status, applied_at, status_updated_at
            )
            VALUES (?, ?, 'new', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (vacancy_id, candidate_id),
        )
        application_id = cursor.lastrowid

        # ------------------------------------------------------------
        # 6) Seed a demo interview (phase 1) + assign interviewer (multi-interviewer table)
        # ------------------------------------------------------------
        print("Seeding a demo interview + interviewer assignment...")

        first_phase_id = cursor.execute(
            """
            SELECT id
            FROM interview_phases
            WHERE vacancy_id = ? AND sequence_number = 1
            """,
            (vacancy_id,),
        ).fetchone()[0]

        cursor.execute(
            """
            INSERT INTO interviews (
                application_id, phase_id, scheduled_start, scheduled_end, location, meeting_link,
                status, created_by_user_id, created_at
            )
            VALUES (?, ?, DATETIME('now', '+1 day'), DATETIME('now', '+1 day', '+1 hour'),
                    ?, ?, 'planned', ?, CURRENT_TIMESTAMP)
            """,
            (
                application_id,
                first_phase_id,
                "HQ Meeting Room 1",
                "https://example.com/meeting-link",
                recruiter_user_id,
            ),
        )
        interview_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO interview_interviewers (interview_id, interviewer_user_id, interviewer_role)
            VALUES (?, ?, 'primary')
            """,
            (interview_id, interviewer_user_id),
        )

        # Optional: create an empty draft evaluation to demonstrate the flow
        cursor.execute(
            """
            INSERT INTO evaluations (
                interview_id, interviewer_user_id, template_version_id, evaluation_status, created_at
            )
            VALUES (?, ?, ?, 'draft', CURRENT_TIMESTAMP)
            """,
            (interview_id, interviewer_user_id, template_version_id),
        )

        database_connection.commit()

        print("-" * 40)
        print("Database reset complete!")
        print(f"Database file: {DATABASE_PATH}")
        print("Seeded users (password = 'admin'):")
        print(" - recruiter@bedrijf.be")
        print(" - manager@bedrijf.be")
        print(" - interviewer@bedrijf.be")
        print(" - admin@bedrijf.be")
        print("Seeded candidate (password = 'admin'):")
        print(" - kandidaat@voorbeeld.be")

    finally:
        database_connection.close()


if __name__ == "__main__":
    initialize_database()
