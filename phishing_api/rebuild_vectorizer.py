"""
rebuild_vectorizer.py
─────────────────────
Run this ONCE with your original dataset to recreate and save vectorizer.pkl.

Usage:
    python rebuild_vectorizer.py --dataset path/to/phishing_site_urls.csv

The CSV must have columns: URL, Label  (Label values: 'good' | 'bad')
"""

import argparse
import joblib
import pandas as pd
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer
from sklearn.feature_extraction.text import CountVectorizer

def process_url(url: str, tokenizer, stemmer) -> str:
    tokens = tokenizer.tokenize(url)
    return ' '.join([stemmer.stem(t) for t in tokens])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="Path to phishing_site_urls.csv")
    parser.add_argument("--output",  default="vectorizer.pkl", help="Where to save vectorizer")
    args = parser.parse_args()

    print(f"Loading dataset from {args.dataset} ...")
    df = pd.read_csv(args.dataset)

    tokenizer = RegexpTokenizer(r'[A-Za-z]+')
    stemmer   = SnowballStemmer('english')

    print("Tokenizing and stemming URLs ...")
    df['text'] = df['URL'].map(lambda u: process_url(u, tokenizer, stemmer))

    print("Fitting CountVectorizer ...")
    cv = CountVectorizer()
    cv.fit(df['text'])

    joblib.dump(cv, args.output)
    print(f"✅  Vectorizer saved to {args.output}  (vocab size: {len(cv.vocabulary_)})")

if __name__ == "__main__":
    main()
