# parser.py
import re
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer

# Must match normalize_url in modetSetup.ipynb so serving input matches training input
SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
URL_RE = re.compile(r'''https?://[^\s<>"'()]+|www\.[^\s<>"'()]+''', re.IGNORECASE)
TRAILING_PUNCT = '.,;:!?]}>'


def normalize_url(url: str) -> str:
    return SCHEME_RE.sub('', url.strip())


class EmailParser:
    def __init__(self):
        self.tokenizer = RegexpTokenizer(r'[A-Za-z]+')
        self.stemmer = SnowballStemmer('english')

    def process_url(self, url: str) -> str:
        """Normalize, tokenize and stem a single URL for the ML model."""
        tokens = self.tokenizer.tokenize(normalize_url(url))
        return ' '.join([self.stemmer.stem(t) for t in tokens])

    def extract_and_process(self, raw_email: str) -> dict:
        """
        Extracts URLs and the email body from raw email text,
        then tokenizes + stems each URL for the ML model.
        """
        body_text = self._extract_body(raw_email)
        urls = self._extract_urls(raw_email)

        body_tokens = self.tokenizer.tokenize(body_text)
        processed_body = ' '.join([self.stemmer.stem(w) for w in body_tokens])

        processed_urls = []
        for url in urls:
            processed_urls.append({
                "raw": url,
                "processed": self.process_url(url)
            })

        return {
            "processed_body": processed_body,
            "urls": urls,
            "processed_urls": processed_urls,
        }

    def _extract_body(self, text: str) -> str:
        lines = text.splitlines()
        body_lines = []
        in_header = True
        for line in lines:
            if in_header and re.match(r'^(From|To|Subject|Date|CC|BCC|Reply-To):', line, re.IGNORECASE):
                continue
            else:
                in_header = False
                body_lines.append(line)
        return '\n'.join(body_lines)

    def _extract_urls(self, text: str) -> list:
        """Finds URLs, trims sentence punctuation, and drops duplicates (order preserved)."""
        urls = (m.rstrip(TRAILING_PUNCT) for m in URL_RE.findall(text))
        return list(dict.fromkeys(u for u in urls if u))
