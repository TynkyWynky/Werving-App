<div align="center"> <!-- Optional: Add your logo file at: /assets/logo.png --> <!-- <img src="assets/logo.png" alt="Werving App Logo" width="120" /> -->
Werving App

A recruitment & selection platform to manage vacancies, candidates, interviews and structured evaluations.

<br/> <!-- Badges -->

<a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white"></a>
<a href="https://flask.palletsprojects.com/"><img alt="Flask" src="https://img.shields.io/badge/Flask-000000?logo=flask&logoColor=white"></a>
<img alt="Database" src="https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white">
<img alt="Platform" src="https://img.shields.io/badge/Platform-Web-brightgreen">
<img alt="License" src="https://img.shields.io/badge/License-MIT-blue">

<br/> <br/> <!-- Optional screenshot: put a file at /assets/preview.png --> <!-- <img src="assets/preview.png" alt="App Preview" width="900" /> --> </div>
✨ Features

Vacancy workflow

Create vacancy requests (Hiring Manager)

Validate & publish vacancies (Recruiter)

Close / archive vacancies

Candidate portal

Apply to published vacancies

Upload CV (PDF/DOCX) and motivation

Track application status and optionally withdraw

Screening & shortlist

Filter candidates by status

Shortlist management for interview rounds

Interview planning

Hiring Manager assigns interviewers

Recruiter schedules interviews & sends invitations (mail)

Optional online meeting link (Teams/Zoom/...)

Structured evaluations (UC-08)

Recruiter evaluates interview round 1

Interviewers evaluate round 2+

Fixed criteria templates + total overview for decision-making

👥 Roles

Hiring Manager — requests vacancies, assigns interviewers, reviews results and makes the final decision

Recruiter (HR) — validates/publishes vacancies, screens candidates, schedules interviews, conducts round 1, manages templates

Interviewer — evaluates candidates in round 2+ using structured templates

Candidate — applies, uploads documents, tracks status

🧰 Tech Stack

Python 3

Flask

SQLite

SMTP email (Microsoft 365 / Outlook supported)

🚀 Getting Started
Prerequisites

Python 3.x

pip

Setup (Windows)

Create & activate a virtual environment

python -m venv venv
venv\Scripts\activate


Install requirements

pip install -r requirements.txt


Initialize the database

python init_db.py


Run the application

python app.py


Seed the database (demo data)

python seed_demo_data.py --reset


Note: --reset clears the existing database before seeding.

🔧 Environment Variables

Create a .env file in the project root:

# SMTP Microsoft 365 / Outlook
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=1

SMTP_USERNAME=your_email@example.com
SMTP_PASSWORD=your_app_password

SMTP_FROM_EMAIL=your_email@example.com
SMTP_FROM_NAME=Werving App

# optional
FLASK_SECRET_KEY=your_long_random_string
MAX_UPLOAD_BYTES=10485760
FLASK_SESSION_SECURE=0
SQLITE_TIMEOUT_SECONDS=15

📝 Notes

Add venv/ and .env to your .gitignore (don’t commit secrets).

If SMTP login fails, use an App Password where possible.

📄 License

MIT (or update to match your repository license)