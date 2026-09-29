# Phishing Website Detection System Using Machine Learning

A web app that checks URLs and emails for phishing links. A logistic regression model, trained on more than 500,000 labelled URLs, scores each link and shows which words in it drove the verdict.

**Live demo:** https://YOUR-PROJECT.vercel.app

## Features

- **URL check.** Paste a link to get its phishing probability, a risk level, and the tokens that pushed the model toward "phishing" or "legitimate".
- **Email scan.** Paste an email. Every link is extracted and scored on its own, and the email gets an overall verdict.
- **Trusted domains.** A short whitelist of well-known sites (github.com, google.com, paypal.com, and so on) prevents common false positives. Lookalikes such as `paypal.com.secure-verify.ru` are still scored by the model.
- **Zero-retention mode.** Email content is processed in memory and never stored.

## Model

The model is built in [`modetSetup.ipynb`](modetSetup.ipynb):

1. **Clean.** Strip the `http://` / `https://` prefix and remove duplicate URLs.
2. **Tokenize and stem.** Split each URL into alphabetic tokens (`RegexpTokenizer`) and reduce them to stems (`SnowballStemmer`).
3. **Vectorize.** Turn the tokens into a bag-of-words vector with `CountVectorizer`.
4. **Classify.** `LogisticRegression` outputs the probability that a URL is phishing. At 50% or above, the URL is flagged.

Results on a held-out 20% test split:

| Metric | Score |
|---|---|
| Accuracy | 96.5% |
| Phishing precision | 96.5% |
| Phishing recall | 87.8% |

Dataset: [Phishing Site URLs (Kaggle)](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls), 549,346 URLs. That is 507,190 after removing duplicates.

**Limitations:** the model only reads the words in a URL. It does not see page content or domain reputation, so words that are common in phishing kits (`login`, `mail`, `paypal`) can flag legitimate pages. The trusted-domain list covers the most common cases.

## Tech stack

- **Model:** Python, scikit-learn, NLTK, pandas (Jupyter)
- **API:** FastAPI
- **Frontend:** React, Vite, Tailwind CSS
- **Hosting:** Vercel. The frontend is served as static files, and the API runs as a Python serverless function under `/api`.

## Project structure

```
modetSetup.ipynb        Model training and evaluation; exports the .pkl files
phishing_api/
  main.py               FastAPI app: /health, /predict, /analyze
  parser.py             URL normalization, tokenizing, email link extraction
  privacy.py            Zero-retention handling
  phishing.pkl          Trained model
  vectorizer.pkl        Fitted CountVectorizer
api/index.py            Vercel entry point (serves the API under /api)
frontend/               React app
vercel.json             Vercel build and routing config
```

## Run locally

Requirements: Python 3.12 or later, and Node 18 or later.

**1. Start the API** (http://localhost:8000):

```bash
python -m venv venv
venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
pip install -r phishing_api/requirements.txt
uvicorn main:app --app-dir phishing_api --port 8000
```

**2. Start the frontend** in a second terminal (http://localhost:5173):

```bash
cd frontend
npm install
npm run dev
```

## Deploy to Vercel

1. Import the GitHub repository into [Vercel](https://vercel.com/new). Leave the Root Directory set to the repository root.
2. Click **Deploy**. `vercel.json` handles the build, and the root `requirements.txt` installs the API's dependencies.

After deploying, open `https://YOUR-PROJECT.vercel.app/api/health`. It should return `{"status": "ok", ...}`. The first request after a period of inactivity can take a few seconds while the function starts up.

## Retraining the model

Run every cell in `modetSetup.ipynb` from the repository root with `phishing_site_urls.csv` present. The final cell overwrites `phishing_api/phishing.pkl` and `phishing_api/vectorizer.pkl`. Use scikit-learn 1.7.2, the version pinned in both `requirements.txt` files, so the saved model loads the same way everywhere.

## API

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/api/health` | none | Service status |
| POST | `/api/predict` | `{"url": "..."}` | Verdict, probability, risk level, and token signals for one URL |
| POST | `/api/analyze` | `{"raw_email": "...", "privacy_mode": true}` | Overall verdict plus per-link results |

When running locally, drop the `/api` prefix (for example, `http://localhost:8000/predict`).

## Author

Daniel Cornett
