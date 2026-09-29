# main.py
import os
import re
import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from parser import EmailParser
from privacy import PrivacyManager

<<<<<<< HEAD
# Load model + vectorizer (both exported together by modetSetup.ipynb)
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH      = os.getenv("MODEL_PATH",      os.path.join(BASE_DIR, "phishing.pkl"))
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", os.path.join(BASE_DIR, "vectorizer.pkl"))
=======
# ── NLTK bootstrap ────────────────────────────────────────────────────────────
nltk.download('punkt', quiet=True)
nltk.download('punkt_tab', quiet=True)

# ── Load model + vectorizer ───────────────────────────────────────────────────
MODEL_PATH      = os.getenv("MODEL_PATH",      "phishing.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "vectorizer.pkl")
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0

model      = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

<<<<<<< HEAD
BAD_IDX       = list(model.classes_).index("bad")
FEATURE_NAMES = vectorizer.get_feature_names_out()
# coef_ is expressed toward classes_[1]; flip it so positive always means "toward phishing"
PHISH_COEF    = model.coef_[0] if BAD_IDX == 1 else -model.coef_[0]

# App setup
=======
# ── App setup ─────────────────────────────────────────────────────────────────
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0
app = FastAPI(
    title="Anti-Phishing Detection API",
    description="Scans email URLs and returns a phishing risk assessment.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

parser = EmailParser()

# ── Trusted domain whitelist ──────────────────────────────────────────────────
# Well-known legitimate domains that the model may incorrectly flag.
# A URL whose registered domain matches one of these is always marked SAFE.
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googlemail.com",
    "github.com", "githubusercontent.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "wikipedia.org",
    "stackoverflow.com",
    "reddit.com",
    "netflix.com",
    "spotify.com",
    "paypal.com",          # only the real paypal.com, not paypal-anything.xyz
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",
    "notion.so",
    "cloudflare.com",
    "mozilla.org", "firefox.com",
    "adobe.com",
    "salesforce.com",
    "shopify.com",
}

def _extract_registered_domain(url: str) -> str:
    """
    Returns the registered domain (e.g. 'github.com') from a URL.
    Handles subdomains like docs.github.com → github.com.
    """
    try:
        # Strip scheme
        host = re.sub(r'^https?://', '', url).split('/')[0].split('?')[0].split(':')[0].lower()
        parts = host.split('.')
        # Return last two parts as registered domain
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception:
        return ''

def _is_trusted(url: str) -> bool:
    return _extract_registered_domain(url) in TRUSTED_DOMAINS

# ── Request / Response models ─────────────────────────────────────────────────
class EmailRequest(BaseModel):
<<<<<<< HEAD
    raw_email: str = Field(min_length=1)
    privacy_mode: bool = True   # Secure by default (never logs data)
=======
    raw_email: str
    privacy_mode: bool = True
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0

class URLRequest(BaseModel):
    url: str = Field(min_length=1)

class Signal(BaseModel):
    token: str
    weight: float               # > 0 pushes toward phishing, < 0 toward safe

class URLResult(BaseModel):
    url: str
    is_phishing: bool
<<<<<<< HEAD
    phishing_probability: float # 0.0 -> 1.0
    risk_level: str             # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    signals: list[Signal]
=======
    confidence: float
    risk_level: str
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0

class URLPredictResponse(URLResult):
    verdict: str
    message: str

class AnalysisResponse(BaseModel):
<<<<<<< HEAD
    overall_verdict: str        # "SAFE" | "SUSPICIOUS" | "PHISHING"
    overall_probability: float
=======
    overall_verdict: str
    overall_confidence: float
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0
    warning_message: str
    url_results: list[URLResult]
    urls_found: int
    phishing_urls_found: int

<<<<<<< HEAD
# Helper Funcs
=======
# ── Helpers ───────────────────────────────────────────────────────────────────
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0
def _risk_level(prob: float) -> str:
    if prob < 0.40:
        return "LOW"
    elif prob < 0.65:
        return "MEDIUM"
    elif prob < 0.85:
        return "HIGH"
    else:
        return "CRITICAL"

<<<<<<< HEAD
def _signals(vec, top_n: int = 6) -> list[Signal]:
    """Tokens in this URL ranked by how much they moved the prediction."""
    contributions = [
        (FEATURE_NAMES[i], float(PHISH_COEF[i] * count))
        for i, count in zip(vec.indices, vec.data)
    ]
    contributions.sort(key=lambda c: abs(c[1]), reverse=True)
    return [Signal(token=t, weight=round(w, 3)) for t, w in contributions[:top_n]]

def score_url(raw_url: str, processed_url: str) -> URLResult:
    vec  = vectorizer.transform([processed_url])
    prob = float(model.predict_proba(vec)[0][BAD_IDX])
    return URLResult(
        url                  = raw_url,
        is_phishing          = prob >= 0.5,
        phishing_probability = round(prob, 4),
        risk_level           = _risk_level(prob),
        signals              = _signals(vec),
    )

def _verdict(phishing_urls: int, total_urls: int, max_prob: float) -> tuple[str, str]:
    """Returns (verdict, warning_message)."""
    if total_urls == 0:
        return "SAFE", "No URLs detected in this email."

    if phishing_urls == 0:
        return "SAFE", "All URLs in this email appear legitimate."

=======
def _score_url(raw_url: str) -> tuple[float, bool]:
    """
    Returns (phish_probability, was_whitelisted).
    Whitelisted domains always return 0.0.
    """
    if _is_trusted(raw_url):
        return 0.0, True

    processed = parser.process_url(raw_url)
    vec = vectorizer.transform([processed])
    proba   = model.predict_proba(vec)[0]
    classes = list(model.classes_)
    bad_idx = classes.index("bad") if "bad" in classes else 0
    return float(proba[bad_idx]), False

def _verdict(phishing_urls: int, total_urls: int, max_conf: float) -> tuple[str, str]:
    if total_urls == 0:
        return "SAFE", "✅ No URLs detected in this email."
    if phishing_urls == 0:
        return "SAFE", "✅ All URLs in this email appear legitimate."
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0
    ratio = phishing_urls / total_urls
    if max_prob >= 0.85 or ratio >= 0.5:
        verdict = "PHISHING"
        msg = (
            f"This email is very likely a phishing attempt. "
            f"{phishing_urls} of {total_urls} URL(s) flagged as malicious "
            f"(up to {max_prob*100:.1f}% probability). Do not click any links."
        )
    else:
        verdict = "SUSPICIOUS"
        msg = (
            f"This email contains suspicious URL(s). "
            f"{phishing_urls} of {total_urls} URL(s) may be malicious "
            f"(up to {max_prob*100:.1f}% probability). Proceed carefully."
        )
    return verdict, msg

# ── Inference function ────────────────────────────────────────────────────────
def run_inference(features: dict) -> dict:
<<<<<<< HEAD
    url_results = [
        score_url(entry["raw"], entry["processed"])
        for entry in features.get("processed_urls", [])
    ]
=======
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
        raw_url = entry["raw"]
        phish_prob, whitelisted = _score_url(raw_url)
        is_phishing = phish_prob >= 0.5

        url_results.append(URLResult(
            url         = raw_url,
            is_phishing = is_phishing,
            confidence  = round(phish_prob, 4),
            risk_level  = _risk_level(phish_prob),
        ))
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0

    phishing_urls = [r for r in url_results if r.is_phishing]
    max_prob      = max((r.phishing_probability for r in url_results), default=0.0)
    verdict, msg  = _verdict(len(phishing_urls), len(url_results), max_prob)

    return {
        "overall_verdict":     verdict,
        "overall_probability": round(max_prob, 4),
        "warning_message":     msg,
        "url_results":         [r.model_dump() for r in url_results],
        "urls_found":          len(url_results),
        "phishing_urls_found": len(phishing_urls),
    }

<<<<<<< HEAD
# Routes
=======
# ── Routes ────────────────────────────────────────────────────────────────────
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0
@app.get("/health")
async def health():
    return {"status": "ok", "model": os.path.basename(MODEL_PATH), "vocabulary_size": len(FEATURE_NAMES)}

@app.post("/predict", response_model=URLPredictResponse)
async def predict_url(request: URLRequest):
<<<<<<< HEAD
    """Check a single URL directly, no email needed."""
    result = score_url(request.url, parser.process_url(request.url))
    prob   = result.phishing_probability

    if prob >= 0.85:
        verdict, message = "PHISHING", f"This URL appears malicious ({prob*100:.1f}% probability). Do not visit it."
    elif result.is_phishing:
        verdict, message = "SUSPICIOUS", f"This URL looks suspicious ({prob*100:.1f}% probability). Proceed with caution."
    else:
        verdict, message = "SAFE", f"This URL appears safe ({(1-prob)*100:.1f}% probability of being legitimate)."
=======
    """Check a single URL directly — no email needed."""
    prob, whitelisted = _score_url(request.url)
    is_phishing = prob >= 0.5
    risk = _risk_level(prob)

    if whitelisted:
        verdict = "SAFE"
        message = "✅ This domain is on the trusted whitelist and appears safe."
    elif is_phishing:
        verdict = "PHISHING" if prob >= 0.85 else "SUSPICIOUS"
        message = (
            f"🚨 This URL appears malicious ({prob*100:.1f}% confidence). Do NOT visit."
            if prob >= 0.85 else
            f"⚠️ This URL looks suspicious ({prob*100:.1f}% confidence). Proceed with caution."
        )
    else:
        verdict = "SAFE"
        message = f"✅ This URL appears safe ({(1-prob)*100:.1f}% confidence)."
>>>>>>> f11ade01cab550d136a7b9192f80aabd47ad93c0

    return URLPredictResponse(**result.model_dump(), verdict=verdict, message=message)

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailRequest):
    parsed_features = parser.extract_and_process(request.raw_email)

    result = PrivacyManager.evaluate_payload(
        email_data         = parsed_features,
        is_private         = request.privacy_mode,
        model_predict_func = run_inference,
    )

    return result
