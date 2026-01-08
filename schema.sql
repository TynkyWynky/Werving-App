-- schema.sql (v2)
-- NOTE: This schema is designed for SQLite.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

-- Drop children first (safer when foreign keys are enabled)
DROP TABLE IF EXISTS evaluation_scores;
DROP TABLE IF EXISTS evaluations;

DROP TABLE IF EXISTS interview_interviewers;
DROP TABLE IF EXISTS interviews;
DROP TABLE IF EXISTS interview_phases;

DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS candidates;

DROP TABLE IF EXISTS template_aspects;
DROP TABLE IF EXISTS template_versions;
DROP TABLE IF EXISTS template_groups;

DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS audit_log;

DROP TABLE IF EXISTS vacancies;
DROP TABLE IF EXISTS users;

COMMIT;

PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

-- ------------------------------------------------------------
-- 1) Users (internal users: manager/recruiter/interviewer/admin)
-- ------------------------------------------------------------
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_address TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    user_role TEXT NOT NULL
        CHECK (user_role IN ('manager', 'recruiter', 'interviewer', 'admin')),
    is_active INTEGER NOT NULL DEFAULT 1
        CHECK (is_active IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ------------------------------------------------------------
-- 2) Candidates (external users)
-- Candidates can log in to view/withdraw applications.
-- ------------------------------------------------------------
CREATE TABLE candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_address TEXT NOT NULL UNIQUE,
    password_hash TEXT, -- allow NULL if later you want "invite/set password"
    full_name TEXT NOT NULL,
    phone_number TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
        CHECK (is_active IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);
ALTER TABLE candidates ADD COLUMN set_password_token TEXT;
ALTER TABLE candidates ADD COLUMN set_password_expires_at TEXT;

-- ------------------------------------------------------------
-- 3) Vacancies (created by manager, reviewed by recruiter)
-- ------------------------------------------------------------
CREATE TABLE vacancies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    title TEXT NOT NULL,
    department TEXT NOT NULL,
    description TEXT NOT NULL,

    location TEXT,
    employment_type TEXT, -- e.g. full-time, part-time, internship
    experience_level TEXT, -- e.g. junior, medior, senior

    manager_id INTEGER NOT NULL,

    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'pending_review', 'changes_requested', 'published', 'closed')),

    review_comment TEXT,

    submitted_at TIMESTAMP,
    reviewed_by_user_id INTEGER,
    reviewed_at TIMESTAMP,
    published_at TIMESTAMP,
    closed_at TIMESTAMP,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,

    FOREIGN KEY (manager_id) REFERENCES users (id) ON DELETE RESTRICT,
    FOREIGN KEY (reviewed_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_vacancies_status ON vacancies(status);
CREATE INDEX idx_vacancies_manager ON vacancies(manager_id);

-- ------------------------------------------------------------
-- 4) Templates (group + versions + aspects)
-- This enables template management + versioning.
-- ------------------------------------------------------------
CREATE TABLE template_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT NOT NULL UNIQUE,
    template_description TEXT,
    created_by_user_id INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE template_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_group_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    version_label TEXT, -- optional human label like "v1 - Screening"
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'published', 'archived')),
    created_by_user_id INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,

    FOREIGN KEY (template_group_id) REFERENCES template_groups (id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL,

    UNIQUE (template_group_id, version_number)
);

CREATE INDEX idx_template_versions_group ON template_versions(template_group_id);
CREATE INDEX idx_template_versions_status ON template_versions(status);

CREATE TABLE template_aspects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_version_id INTEGER NOT NULL,

    aspect_title TEXT NOT NULL,
    aspect_description TEXT,
    weight REAL NOT NULL DEFAULT 1.0,
    min_score INTEGER NOT NULL DEFAULT 1,
    max_score INTEGER NOT NULL DEFAULT 5,
    is_required INTEGER NOT NULL DEFAULT 1
        CHECK (is_required IN (0, 1)),
    sort_order INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (template_version_id) REFERENCES template_versions (id) ON DELETE CASCADE
);

CREATE INDEX idx_template_aspects_version ON template_aspects(template_version_id);

-- ------------------------------------------------------------
-- 5) Applications (vacancy <-> candidate)
-- Includes withdraw + CV storage per application.
-- ------------------------------------------------------------
CREATE TABLE applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vacancy_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,

    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN (
            'new',
            'in_review',
            'shortlisted',
            'interview',
            'rejected',
            'offered',
            'hired',
            'withdrawn'
        )),

    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    gdpr_consent INTEGER NOT NULL DEFAULT 0
        CHECK (gdpr_consent IN (0, 1)),
    gdpr_consent_at TIMESTAMP,


    -- Candidate withdrawal
    withdrawn_at TIMESTAMP,
    withdrawn_reason TEXT,

    -- Status change tracking
    status_updated_at TIMESTAMP,
    status_updated_by_user_id INTEGER,
    status_updated_by_candidate_id INTEGER,

    -- Candidate documents/messages
    cover_letter TEXT,
    resume_original_filename TEXT,
    resume_storage_filename TEXT, -- safe random filename stored on disk

    -- Optional token if you later want "view status without password"
    status_view_token TEXT UNIQUE,

    FOREIGN KEY (vacancy_id) REFERENCES vacancies (id) ON DELETE CASCADE,
    FOREIGN KEY (candidate_id) REFERENCES candidates (id) ON DELETE CASCADE,
    FOREIGN KEY (status_updated_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (status_updated_by_candidate_id) REFERENCES candidates (id) ON DELETE SET NULL
);

CREATE INDEX idx_applications_vacancy ON applications(vacancy_id);
CREATE INDEX idx_applications_candidate ON applications(candidate_id);
CREATE INDEX idx_applications_status ON applications(status);

-- ------------------------------------------------------------
-- 6) Interview phases per vacancy (phase order + template per phase)
-- ------------------------------------------------------------
CREATE TABLE interview_phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vacancy_id INTEGER NOT NULL,
    phase_name TEXT NOT NULL,
    sequence_number INTEGER NOT NULL DEFAULT 1,
    template_version_id INTEGER NOT NULL,

    is_active INTEGER NOT NULL DEFAULT 1
        CHECK (is_active IN (0, 1)),

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (vacancy_id) REFERENCES vacancies (id) ON DELETE CASCADE,
    FOREIGN KEY (template_version_id) REFERENCES template_versions (id) ON DELETE RESTRICT,

    UNIQUE (vacancy_id, sequence_number)
);

CREATE INDEX idx_interview_phases_vacancy ON interview_phases(vacancy_id);

-- ------------------------------------------------------------
-- 7) Interviews (scheduled sessions for an application + a phase)
-- ------------------------------------------------------------
CREATE TABLE interviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    phase_id INTEGER NOT NULL,

    scheduled_start TIMESTAMP NOT NULL,
    scheduled_end TIMESTAMP,
    location TEXT,
    meeting_link TEXT,

    status TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned', 'completed', 'cancelled')),

    created_by_user_id INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,

    notes TEXT,

    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (phase_id) REFERENCES interview_phases (id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_interviews_application ON interviews(application_id);
CREATE INDEX idx_interviews_phase ON interviews(phase_id);
CREATE INDEX idx_interviews_status ON interviews(status);

-- Multi-interviewer support
CREATE TABLE interview_interviewers (
    interview_id INTEGER NOT NULL,
    interviewer_user_id INTEGER NOT NULL,
    interviewer_role TEXT NOT NULL DEFAULT 'panel'
        CHECK (interviewer_role IN ('primary', 'panel')),
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notified_at TIMESTAMP,

    PRIMARY KEY (interview_id, interviewer_user_id),

    FOREIGN KEY (interview_id) REFERENCES interviews (id) ON DELETE CASCADE,
    FOREIGN KEY (interviewer_user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 8) Evaluations (one evaluation per interviewer per interview)
-- Stored with template_version_id so later template edits don't break scoring.
-- ------------------------------------------------------------
CREATE TABLE evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interview_id INTEGER NOT NULL,
    interviewer_user_id INTEGER NOT NULL,
    template_version_id INTEGER NOT NULL,

    evaluation_status TEXT NOT NULL DEFAULT 'draft'
        CHECK (evaluation_status IN ('draft', 'submitted')),

    overall_comment TEXT,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    submitted_at TIMESTAMP,

    FOREIGN KEY (interview_id) REFERENCES interviews (id) ON DELETE CASCADE,
    FOREIGN KEY (interviewer_user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (template_version_id) REFERENCES template_versions (id) ON DELETE RESTRICT,

    UNIQUE (interview_id, interviewer_user_id)
);

CREATE INDEX idx_evaluations_interview ON evaluations(interview_id);
CREATE INDEX idx_evaluations_interviewer ON evaluations(interviewer_user_id);

-- Scores per aspect (links to template_aspects)
CREATE TABLE evaluation_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluation_id INTEGER NOT NULL,
    template_aspect_id INTEGER NOT NULL,

    score INTEGER NOT NULL,
    comment TEXT,

    FOREIGN KEY (evaluation_id) REFERENCES evaluations (id) ON DELETE CASCADE,
    FOREIGN KEY (template_aspect_id) REFERENCES template_aspects (id) ON DELETE RESTRICT,

    UNIQUE (evaluation_id, template_aspect_id)
);

CREATE INDEX idx_evaluation_scores_eval ON evaluation_scores(evaluation_id);

-- ------------------------------------------------------------
-- 9) Notifications (optional: email/in-app tracking)
-- You can implement as "logged notifications" if email not required.
-- ------------------------------------------------------------
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    recipient_type TEXT NOT NULL
        CHECK (recipient_type IN ('user', 'candidate')),
    recipient_id INTEGER NOT NULL,

    channel TEXT NOT NULL DEFAULT 'in_app'
        CHECK (channel IN ('in_app', 'email')),

    subject TEXT,
    body TEXT NOT NULL,

    delivery_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_status IN ('pending', 'sent', 'failed')),

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    error_message TEXT
);

CREATE INDEX idx_notifications_recipient ON notifications(recipient_type, recipient_id);
CREATE INDEX idx_notifications_status ON notifications(delivery_status);

-- ------------------------------------------------------------
-- 10) Audit log (status changes, publish actions, evaluation submit, etc.)
-- ------------------------------------------------------------
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_type TEXT NOT NULL,       -- e.g. 'application_status_changed', 'vacancy_published', 'evaluation_submitted'
    entity_type TEXT NOT NULL,      -- e.g. 'application', 'vacancy', 'evaluation', 'interview'
    entity_id INTEGER NOT NULL,

    performed_by_user_id INTEGER,
    performed_by_candidate_id INTEGER,

    from_status TEXT,
    to_status TEXT,

    details_json TEXT,              -- store extra structured details as JSON string

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (performed_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (performed_by_candidate_id) REFERENCES candidates (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS phase_interviewers (
  phase_id INTEGER NOT NULL,
  interviewer_user_id INTEGER NOT NULL,
  PRIMARY KEY (phase_id, interviewer_user_id),
  FOREIGN KEY (phase_id) REFERENCES interview_phases(id) ON DELETE CASCADE,
  FOREIGN KEY (interviewer_user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);

COMMIT;
