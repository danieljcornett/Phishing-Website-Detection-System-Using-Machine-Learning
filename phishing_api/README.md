# 🛡️ Anti-Phishing Detection API

FastAPI backend that scans emails for phishing URLs using a trained Logistic Regression model.

---

## Project Structure

```
phishing_api/
├── main.py                  # FastAPI app — main entry point
├── parser.py                # Email URL extractor + NLP preprocessor
├── privacy.py               # Privacy-safe inference wrapper
├── rebuild_vectorizer.py    # One-time script to regenerate vectorizer.pkl
├── requirements.txt
├── phishing.pkl             # Your trained LogisticRegression model
└── vectorizer.pkl           # CountVectorizer (you must generate this — see Step 1)
```

---

## ⚠️ Step 1 — Rebuild the Vectorizer (required!)

Your `phishing.pkl` only contains the model, not the `CountVectorizer` used to transform URLs.
You need to regenerate it using your original dataset:

```bash
python rebuild_vectorizer.py --dataset path/to/phishing_site_urls.csv
```

This creates `vectorizer.pkl` in the same folder. **Both `.pkl` files must be present to run the API.**

---

## Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

---

## Step 3 — Run the API

```bash
uvicorn main:app --reload
```

The API is now live at `http://127.0.0.1:8000`

Interactive docs: `http://127.0.0.1:8000/docs`

---

## API Endpoints

### `GET /health`
Returns API status.

```json
{ "status": "ok", "model": "phishing.pkl", "vectorizer": "vectorizer.pkl" }
```

---

### `POST /analyze`

Scan an email for phishing URLs.

**Request body:**
```json
{
  "raw_email": "Hey click this link http://totally-legit-bank.ru/login now!",
  "privacy_mode": true
}
```

**Response:**
```json
{
  "overall_verdict": "PHISHING",
  "overall_confidence": 0.9231,
  "warning_message": "🚨 WARNING: This email is very likely a phishing attempt! 1 of 1 URL(s) flagged as malicious (92.3% confidence). Do NOT click any links.",
  "url_results": [
    {
      "url": "http://totally-legit-bank.ru/login",
      "is_phishing": true,
      "confidence": 0.9231,
      "risk_level": "CRITICAL"
    }
  ],
  "urls_found": 1,
  "phishing_urls_found": 1
}
```

**Verdict levels:**
| Verdict | Meaning |
|---------|---------|
| `SAFE` | No phishing URLs detected |
| `SUSPICIOUS` | Some URLs flagged, low-to-medium confidence |
| `PHISHING` | High confidence phishing detected |

**Risk levels:**
| Level | Confidence |
|-------|-----------|
| `LOW` | < 40% |
| `MEDIUM` | 40–65% |
| `HIGH` | 65–85% |
| `CRITICAL` | > 85% |

---

## Privacy Mode

When `privacy_mode: true` (default), the email content is **never logged or stored** — it's processed in-memory only and garbage-collected immediately after inference.

Set `privacy_mode: false` only if you want to collect data for future model retraining.

---

## Deploying to Production

Recommended platforms (free tier available):
- **Railway** — push to GitHub, done in 2 minutes
- **Render** — similar one-click deploy
- **Fly.io** — more control, still simple

For any of these, set environment variables:
```
MODEL_PATH=phishing.pkl
VECTORIZER_PATH=vectorizer.pkl
```
