# StudyForge

A student productivity and attendance management web app built with Flask and SQLite. Includes authentication, per-user tasks, attendance logs, and a clean Bootstrap UI.

## Features
- Authentication: register, login, logout with secure password hashing
- Tasks: add tasks, mark complete, user-scoped
- Attendance: add subject-wise entries with Present/Absent status
- Dashboard: unified view for tasks and attendance

## Requirements
- Python 3.10+
- Windows PowerShell (commands below assume PowerShell)

## Setup
```powershell
# From the project root
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
```

Optionally set a stronger secret key:
```powershell
$env:SECRET_KEY = "your-strong-secret-key"
```

## Run
```powershell
. .venv/Scripts/Activate.ps1
python app.py
```

The app runs at http://127.0.0.1:5000/

## Notes
- Data is stored in `database.db` in the project root.
- Routes requiring auth use a session; logout via navbar.
- To reset data, stop the app and delete `database.db`.