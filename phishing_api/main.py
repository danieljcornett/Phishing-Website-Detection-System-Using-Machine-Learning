# main.py
import os
import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlsplit
from pydantic import BaseModel, Field
from parser import EmailParser, normalize_url
from privacy import PrivacyManager

# Load model + vectorizer (both exported together by modetSetup.ipynb)
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH      = os.getenv("MODEL_PATH",      os.path.join(BASE_DIR, "phishing.pkl"))
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", os.path.join(BASE_DIR, "vectorizer.pkl"))

model      = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

BAD_IDX       = list(model.classes_).index("bad")
FEATURE_NAMES = vectorizer.get_feature_names_out()
# coef_ is expressed toward classes_[1]; flip it so positive always means "toward phishing"
PHISH_COEF    = model.coef_[0] if BAD_IDX == 1 else -model.coef_[0]

# App setup
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

@app.middleware("http")
async def strip_api_prefix(request, call_next):
    """On Vercel the API is public under /api; accept /api/predict as well as /predict."""
    path = request.scope["path"]
    if path == "/api" or path.startswith("/api/"):
        request.scope["path"] = path[4:] or "/"
    return await call_next(request)

parser = EmailParser()

# Trusted domain whitelist
# Well-known legitimate domains the model may incorrectly flag (e.g. github.com/login).
# A URL whose host is one of these, or a subdomain of one, is always marked SAFE.
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googlemail.com",
    "github.com", "githubusercontent.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com",
    "apple.com", "icloud.com",
    "amazon.com",
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

def _host(url: str) -> str:
    """Host of a URL, ignoring any user@ prefix (google.com@evil.ru is evil.ru)."""
    netloc = urlsplit('//' + normalize_url(url)).netloc
    return netloc.rsplit('@', 1)[-1].split(':')[0].lower().rstrip('.')

def _is_trusted(url: str) -> bool:
    host = _host(url)
    return any(host == d or host.endswith('.' + d) for d in TRUSTED_DOMAINS)

# Request / Response models
class EmailRequest(BaseModel):
    raw_email: str = Field(min_length=1)
    privacy_mode: bool = True   # Secure by default (never logs data)

class URLRequest(BaseModel):
    url: str = Field(min_length=1)

class Signal(BaseModel):
    token: str
    weight: float               # > 0 pushes toward phishing, < 0 toward safe

class URLResult(BaseModel):
    url: str
    is_phishing: bool
    phishing_probability: float # 0.0 -> 1.0
    risk_level: str             # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    signals: list[Signal]
    trusted_domain: bool = False  # True when the whitelist decided, not the model

class URLPredictResponse(URLResult):
    verdict: str
    message: str

class AnalysisResponse(BaseModel):
    overall_verdict: str        # "SAFE" | "SUSPICIOUS" | "PHISHING"
    overall_probability: float
    warning_message: str
    url_results: list[URLResult]
    urls_found: int
    phishing_urls_found: int

# Helper Funcs
def _risk_level(prob: float) -> str:
    if prob < 0.40:
        return "LOW"
    elif prob < 0.65:
        return "MEDIUM"
    elif prob < 0.85:
        return "HIGH"
    else:
        return "CRITICAL"

def _signals(vec, top_n: int = 6) -> list[Signal]:
    """Tokens in this URL ranked by how much they moved the prediction."""
    contributions = [
        (FEATURE_NAMES[i], float(PHISH_COEF[i] * count))
        for i, count in zip(vec.indices, vec.data)
    ]
    contributions.sort(key=lambda c: abs(c[1]), reverse=True)
    return [Signal(token=t, weight=round(w, 3)) for t, w in contributions[:top_n]]

def score_url(raw_url: str, processed_url: str) -> URLResult:
    if _is_trusted(raw_url):
        return URLResult(
            url                  = raw_url,
            is_phishing          = False,
            phishing_probability = 0.0,
            risk_level           = "LOW",
            signals              = [],
            trusted_domain       = True,
        )

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

# Inference function (passed into PrivacyManager)
def run_inference(features: dict) -> dict:
    url_results = [
        score_url(entry["raw"], entry["processed"])
        for entry in features.get("processed_urls", [])
    ]

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

# Routes
@app.get("/health")
async def health():
    return {"status": "ok", "model": os.path.basename(MODEL_PATH), "vocabulary_size": len(FEATURE_NAMES)}

@app.post("/predict", response_model=URLPredictResponse)
async def predict_url(request: URLRequest):
    """Check a single URL directly, no email needed."""
    result = score_url(request.url, parser.process_url(request.url))
    prob   = result.phishing_probability

    if result.trusted_domain:
        verdict, message = "SAFE", f"{_host(request.url)} is on the trusted domain list."
    elif prob >= 0.85:
        verdict, message = "PHISHING", f"This URL appears malicious ({prob*100:.1f}% probability). Do not visit it."
    elif result.is_phishing:
        verdict, message = "SUSPICIOUS", f"This URL looks suspicious ({prob*100:.1f}% probability). Proceed with caution."
    else:
        verdict, message = "SAFE", f"This URL appears safe ({(1-prob)*100:.1f}% probability of being legitimate)."

    return URLPredictResponse(**result.model_dump(), verdict=verdict, message=message)

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailRequest):
    parsed_features = parser.extract_and_process(request.raw_email)

    result = PrivacyManager.evaluate_payload(
        email_data        = parsed_features,
        is_private        = request.privacy_mode,
        model_predict_func= run_inference,
    )

    return result
