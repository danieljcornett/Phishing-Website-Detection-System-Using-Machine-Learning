# Vercel serverless entry point: serves the FastAPI app from phishing_api/ under /api
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishing_api"))

from fastapi import FastAPI
from main import app as phishing_app

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/api", phishing_app)
