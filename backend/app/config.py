import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cloudsoc.db")
REPORT_DIR = Path(os.getenv("REPORT_DIR", "../reports"))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
