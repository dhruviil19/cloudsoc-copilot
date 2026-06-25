#!/usr/bin/env bash
set -e

echo "Start backend in one terminal:"
echo "cd backend && uvicorn app.main:app --reload --port 8000"
echo ""
echo "Start dashboard in another terminal:"
echo "cd dashboard && streamlit run streamlit_app.py"
