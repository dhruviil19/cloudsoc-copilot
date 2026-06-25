# Cloud Deployment Guide

This project is ready for container-based deployment, but actual cloud deployment requires your own cloud account.

## Recommended beginner deployment path

Use a service that supports Docker Compose or separate Docker services:

- Render
- Railway
- Fly.io
- AWS Lightsail
- AWS EC2

## Option 1: Deploy on a VM

1. Create an Ubuntu VM.
2. Install Docker and Docker Compose.
3. Clone your GitHub repo.
4. Run:

```bash
docker compose up --build -d
```

5. Open the VM firewall for:

```text
8000 backend API
8501 Streamlit dashboard
```

## Option 2: Deploy backend and dashboard separately

Backend:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Dashboard:

```bash
cd dashboard
BACKEND_API_URL=https://your-backend-url streamlit run streamlit_app.py --server.address 0.0.0.0
```

## Production improvements before public deployment

- Add authentication
- Move SQLite to PostgreSQL
- Restrict CORS origins
- Add rate limiting
- Add persistent object storage for reports
- Add secrets management
- Add HTTPS
