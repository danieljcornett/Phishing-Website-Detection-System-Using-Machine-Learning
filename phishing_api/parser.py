# parser.py
import re
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer


class EmailParser:
    def __init__(self):
        self.tokenizer = RegexpTokenizer(r'[A-Za-z]+')
        self.stemmer = SnowballStemmer('english')

    def extract_and_process(self, raw_email: str) -> dict:
        """
        Extracts URLs and the email body from raw email text,
        then tokenizes + stems each URL for the ML model.
        """
        body_text = self._extract_body(raw_email)
        urls = self._extract_urls(raw_email)

        # Process the email body (for display / future use)
        body_tokens = self.tokenizer.tokenize(body_text)
        processed_body = ' '.join([self.stemmer.stem(w) for w in body_tokens])

        # Process each URL the same way the model was trained:
        # tokenize → stem → join into a single string per URL
        processed_urls = []
        for url in urls:
            tokens = self.tokenizer.tokenize(url)
            stemmed = ' '.join([self.stemmer.stem(t) for t in tokens])
            processed_urls.append({
                "raw": url,
                "processed": stemmed
            })

        return {
            "processed_body": processed_body,
            "urls": urls,
            "processed_urls": processed_urls,
        }

    def _extract_body(self, text: str) -> str:
        # Strip common email headers so they don't pollute URL extraction
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
        url_pattern = re.compile(r'https?://\S+|www\.\S+')
        return url_pattern.findall(text)
