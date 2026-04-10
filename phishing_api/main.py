# main.py
import os
import joblib
import nltk
import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from parser import EmailParser
from privacy import PrivacyManager

# ── NLTK bootstrap ────────────────────────────────────────────────────────────
nltk.download('punkt', quiet=True)
nltk.download('punkt_tab', quiet=True)

# ── Load model + vectorizer ───────────────────────────────────────────────────
MODEL_PATH      = os.getenv("MODEL_PATH",      "phishing.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "vectorizer.pkl")

model      = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Anti-Phishing Detection API",
    description="Scans email URLs and returns a phishing risk assessment.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

parser = EmailParser()

# ── Request / Response models ─────────────────────────────────────────────────
class EmailRequest(BaseModel):
    raw_email: str
    privacy_mode: bool = True   # Secure by default — never logs data

class URLResult(BaseModel):
    url: str
    is_phishing: bool
    confidence: float           # 0.0 → 1.0 probability of being phishing
    risk_level: str             # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

class AnalysisResponse(BaseModel):
    overall_verdict: str        # "SAFE" | "SUSPICIOUS" | "PHISHING"
    overall_confidence: float
    warning_message: str
    url_results: list[URLResult]
    urls_found: int
    phishing_urls_found: int

# ── Helpers ───────────────────────────────────────────────────────────────────
def _risk_level(prob: float) -> str:
    if prob < 0.40:
        return "LOW"
    elif prob < 0.65:
        return "MEDIUM"
    elif prob < 0.85:
        return "HIGH"
    else:
        return "CRITICAL"

def _verdict(phishing_urls: int, total_urls: int, max_conf: float) -> tuple[str, str]:
    """Returns (verdict, warning_message)."""
    if total_urls == 0:
        return "SAFE", "✅ No URLs detected in this email."

    if phishing_urls == 0:
        return "SAFE", "✅ All URLs in this email appear legitimate."

    ratio = phishing_urls / total_urls
    if max_conf >= 0.85 or ratio >= 0.5:
        verdict = "PHISHING"
        msg = (
            f"🚨 WARNING: This email is very likely a phishing attempt! "
            f"{phishing_urls} of {total_urls} URL(s) flagged as malicious "
            f"(up to {max_conf*100:.1f}% confidence). Do NOT click any links."
        )
    else:
        verdict = "SUSPICIOUS"
        msg = (
            f"⚠️  CAUTION: This email contains suspicious URL(s). "
            f"{phishing_urls} of {total_urls} URL(s) may be malicious "
            f"(up to {max_conf*100:.1f}% confidence). Proceed carefully."
        )
    return verdict, msg

# ── Inference function (passed into PrivacyManager) ───────────────────────────
def run_inference(features: dict) -> dict:
    processed_urls = features.get("processed_urls", [])

    if not processed_urls:
        return {
            "overall_verdict": "SAFE",
            "overall_confidence": 0.0,
            "warning_message": "✅ No URLs detected in this email.",
            "url_results": [],
            "urls_found": 0,
            "phishing_urls_found": 0,
        }

    url_results = []
    for entry in processed_urls:
        raw_url       = entry["raw"]
        processed_url = entry["processed"]

        # Vectorize with the same CountVectorizer used during training
        vec = vectorizer.transform([processed_url])

        # Probability of being "bad" (phishing)
        proba        = model.predict_proba(vec)[0]
        classes      = list(model.classes_)          # e.g. ['bad', 'good']
        bad_idx      = classes.index("bad") if "bad" in classes else 0
        phish_prob   = float(proba[bad_idx])
        is_phishing  = phish_prob >= 0.5

        url_results.append(URLResult(
            url         = raw_url,
            is_phishing = is_phishing,
            confidence  = round(phish_prob, 4),
            risk_level  = _risk_level(phish_prob),
        ))

    phishing_urls = [r for r in url_results if r.is_phishing]
    max_conf      = max((r.confidence for r in url_results), default=0.0)
    verdict, msg  = _verdict(len(phishing_urls), len(url_results), max_conf)

    return {
        "overall_verdict":    verdict,
        "overall_confidence": round(max_conf, 4),
        "warning_message":    msg,
        "url_results":        [r.dict() for r in url_results],
        "urls_found":         len(url_results),
        "phishing_urls_found": len(phishing_urls),
    }

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "model": MODEL_PATH, "vectorizer": VECTORIZER_PATH}

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailRequest):
    parsed_features = parser.extract_and_process(request.raw_email)

    result = PrivacyManager.evaluate_payload(
        email_data        = parsed_features,
        is_private        = request.privacy_mode,
        model_predict_func= run_inference,
    )

    return result
