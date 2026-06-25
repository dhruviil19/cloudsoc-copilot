# Setup Guide

## Local setup

```bash
cd cloudsoc-copilot
python3 -m venv .venv
source .venv/bin/activate
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open another terminal:

```bash
cd cloudsoc-copilot
source .venv/bin/activate
cd dashboard
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Open:

```text
http://localhost:8501
```

## Docker setup

```bash
docker compose up --build
```

Open:

```text
Dashboard: http://localhost:8501
Backend API: http://localhost:8000
API docs: http://localhost:8000/docs
```

## Test setup

```bash
cd backend
python3 -m pytest -q
```

Expected result:

```text
5 passed
```
