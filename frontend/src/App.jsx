import React, { useEffect, useRef, useState } from 'react';
import ProbabilityMeter from './components/ProbabilityMeter';
import SignalBars from './components/SignalBars';
import {
  AlertCircleIcon, ChevronDownIcon, LinkIcon, LockIcon, MailIcon,
  ShieldAlertIcon, ShieldCheckIcon, ShieldIcon, ShieldXIcon, SpinnerIcon,
} from './components/icons';
import { RISK, VERDICT } from './risk';

// Local dev talks to uvicorn directly; the Vercel deployment serves the API from /api on the same domain
const API_BASE = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000' : '/api');
const OFFLINE_HINT = import.meta.env.DEV
  ? 'Start it with "uvicorn main:app" from the phishing_api folder.'
  : 'The detection service may be starting up. Wait a few seconds and try again.';

// From the evaluation cells in modetSetup.ipynb (held-out 20% test split)
const MODEL_METRICS = [
  { label: 'Test accuracy',      value: '96.5%' },
  { label: 'Phishing precision', value: '96.5%' },
  { label: 'Phishing recall',    value: '87.8%' },
  { label: 'Training URLs',      value: '507K' },
];

const PIPELINE = [
  { step: '01', title: 'Normalize and tokenize', body: 'The scheme is stripped, then the URL is split into alphabetic tokens and stemmed with a Snowball stemmer.' },
  { step: '02', title: 'Vectorize',             body: 'A CountVectorizer turns the tokens into a bag-of-words vector over a 300K-token vocabulary.' },
  { step: '03', title: 'Classify',              body: 'A logistic regression model outputs the probability that the URL is phishing. 50% or more is flagged.' },
];

const SAMPLES = {
  url: [
    { label: 'Legitimate URL', value: 'https://github.com' },
    { label: 'Phishing URL',   value: 'http://paypal-secure-login.verify-account.xyz' },
  ],
  email: [
    { label: 'Legitimate email', value: 'Hi team, the release notes are up at https://docs.github.com and the recording is on https://www.youtube.com. Thanks!' },
    { label: 'Phishing email',   value: 'URGENT: Your account is suspended. Verify now at http://paypal-login.free-site.ru or lose access permanently.' },
  ],
};

const TABS = [
  { id: 'url',   label: 'Check URL',  Icon: LinkIcon },
  { id: 'email', label: 'Scan email', Icon: MailIcon },
];

const VERDICT_ICON = { SAFE: ShieldCheckIcon, SUSPICIOUS: ShieldAlertIcon, PHISHING: ShieldXIcon };

async function postJson(path, body) {
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    const err = new Error(`Could not reach the API at ${API_BASE}. ${OFFLINE_HINT}`);
    err.offline = true;
    throw err;
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = typeof data?.detail === 'string' ? data.detail : null;
    throw new Error(detail || `The API returned an error (HTTP ${res.status}).`);
  }
  return data;
}

// Components

const RiskChip = ({ level }) => (
  <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-0.5 text-xs font-medium text-ink whitespace-nowrap">
    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: RISK[level].color }} aria-hidden="true" />
    {RISK[level].label}
  </span>
);

const VerdictHeader = ({ verdict, message, children }) => {
  const Icon = VERDICT_ICON[verdict];
  return (
    <div className="flex items-start gap-4">
      <span
        className="flex-none grid place-items-center w-11 h-11 rounded-lg"
        style={{ backgroundColor: `${VERDICT[verdict].color}1f`, color: VERDICT[verdict].color }}
      >
        <Icon className="w-6 h-6" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <h3 className="text-xl font-semibold text-ink">{VERDICT[verdict].label}</h3>
          {children}
        </div>
        <p className="mt-1 text-sm text-ink-muted">{message}</p>
      </div>
    </div>
  );
};

const UrlResult = ({ data }) => (
  <div className="space-y-6">
    <VerdictHeader verdict={data.verdict} message={data.message}>
      <RiskChip level={data.risk_level} />
    </VerdictHeader>
    <p className="rounded-lg bg-raised border border-line px-3 py-2 font-mono text-sm text-ink break-all">{data.url}</p>
    <ProbabilityMeter value={data.phishing_probability} riskLevel={data.risk_level} />
    <SignalBars signals={data.signals} trusted={data.trusted_domain} />
  </div>
);

const Stat = ({ label, value }) => (
  <div className="rounded-lg border border-line bg-raised px-4 py-3">
    <div className="text-xs text-ink-muted">{label}</div>
    <div className="mt-0.5 text-xl font-semibold text-ink">{value}</div>
  </div>
);

const EmailResult = ({ data, privacyMode }) => (
  <div className="space-y-6">
    <VerdictHeader verdict={data.overall_verdict} message={data.warning_message} />

    <div className="grid grid-cols-3 gap-3">
      <Stat label="URLs found" value={data.urls_found} />
      <Stat label="Flagged" value={data.phishing_urls_found} />
      <Stat label="Highest risk" value={`${Math.round(data.overall_probability * 100)}%`} />
    </div>

    {data.url_results.length > 0 && (
      <div>
        <h4 className="text-sm font-medium text-ink mb-2">Links in this email</h4>
        <ul className="space-y-2">
          {data.url_results.map((u, i) => (
            <li key={u.url}>
              <details className="group rounded-lg border border-line bg-raised" open={i === 0 && u.is_phishing}>
                <summary className="flex cursor-pointer list-none items-center gap-3 rounded-lg px-4 py-3 hover:bg-line/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent [&::-webkit-details-marker]:hidden">
                  <span className="min-w-0 flex-1">
                    <span className="block font-mono text-sm text-ink truncate">{u.url}</span>
                    <span className="mt-2 block"><ProbabilityMeter value={u.phishing_probability} riskLevel={u.risk_level} compact /></span>
                  </span>
                  <span className="flex-none text-sm font-semibold tabular-nums text-ink">{Math.round(u.phishing_probability * 100)}%</span>
                  <RiskChip level={u.risk_level} />
                  <ChevronDownIcon className="w-4 h-4 flex-none text-ink-muted motion-safe:transition-transform group-open:rotate-180" />
                </summary>
                <div className="border-t border-line px-4 py-4">
                  <SignalBars signals={u.signals} trusted={u.trusted_domain} />
                </div>
              </details>
            </li>
          ))}
        </ul>
      </div>
    )}

    {privacyMode && (
      <p className="flex items-center gap-2 text-xs text-ink-muted">
        <LockIcon className="w-3.5 h-3.5" />
        Zero-retention mode was on. This email was analyzed in memory and never stored.
      </p>
    )}
  </div>
);

const ApiStatus = ({ status }) => {
  const map = {
    checking: { color: '#8590a3', text: 'Connecting to API' },
    online:   { color: '#0ca30c', text: 'API online' },
    offline:  { color: '#d03b3b', text: 'API offline' },
  };
  return (
    <span className="inline-flex items-center gap-2 text-xs text-ink-muted" role="status">
      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: map[status].color }} aria-hidden="true" />
      {map[status].text}
    </span>
  );
};

// Page

export default function App() {
  const [tab, setTab] = useState('url');
  const [url, setUrl] = useState('');
  const [emailText, setEmailText] = useState('');
  const [privacyMode, setPrivacyMode] = useState(true);
  const [results, setResults] = useState({ url: null, email: null });
  const [errors, setErrors] = useState({ url: null, email: null });
  const [loading, setLoading] = useState(null);
  const [apiStatus, setApiStatus] = useState('checking');
  const tabRefs = useRef({});

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then(res => setApiStatus(res.ok ? 'online' : 'offline'))
      .catch(() => setApiStatus('offline'));
  }, []);

  const run = async (kind, input) => {
    setLoading(kind);
    setErrors(e => ({ ...e, [kind]: null }));
    try {
      const data = kind === 'url'
        ? await postJson('/predict', { url: input.trim() })
        : await postJson('/analyze', { raw_email: input, privacy_mode: privacyMode });
      setResults(r => ({ ...r, [kind]: { data, privacyMode } }));
      setApiStatus('online');
    } catch (e) {
      setResults(r => ({ ...r, [kind]: null }));
      setErrors(er => ({ ...er, [kind]: e.message }));
      if (e.offline) setApiStatus('offline');
    }
    setLoading(null);
  };

  const submit = (e) => {
    e.preventDefault();
    run(tab, tab === 'url' ? url : emailText);
  };

  const runSample = (value) => {
    if (tab === 'url') setUrl(value); else setEmailText(value);
    run(tab, value);
  };

  const onTabKeyDown = (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const next = TABS[(TABS.findIndex(t => t.id === tab) + 1) % TABS.length].id;
    setTab(next);
    tabRefs.current[next]?.focus();
  };

  const input = tab === 'url' ? url : emailText;
  const result = results[tab];
  const error = errors[tab];
  const isLoading = loading === tab;

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-line">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="grid place-items-center w-9 h-9 rounded-lg bg-accent-solid text-white">
              <ShieldIcon className="w-5 h-5" />
            </span>
            <span className="font-semibold tracking-tight">Anti-Phishing Detection</span>
          </div>
          <ApiStatus status={apiStatus} />
        </div>
      </header>

      <main className="flex-1 max-w-6xl mx-auto w-full px-4 sm:px-6 py-10 sm:py-14">
        <section className="max-w-2xl mb-10">
          <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-ink">
            Check a link before you click it
          </h1>
          <p className="mt-3 text-base leading-relaxed text-ink-muted">
            Paste a URL or a full email. A logistic regression model trained on half a million labelled
            URLs scores each link and shows which words in it drove the verdict.
          </p>
        </section>

        <div className="grid gap-6 lg:grid-cols-12 items-start">
          {/* Input panel */}
          <section className="lg:col-span-5 rounded-xl border border-line bg-surface p-5 sm:p-6">
            <div role="tablist" aria-label="Analysis type" className="grid grid-cols-2 gap-1 rounded-lg bg-canvas p-1 mb-6">
              {TABS.map(({ id, label, Icon }) => (
                <button
                  key={id}
                  ref={el => { tabRefs.current[id] = el; }}
                  role="tab"
                  id={`tab-${id}`}
                  aria-selected={tab === id}
                  aria-controls="panel-input"
                  tabIndex={tab === id ? 0 : -1}
                  onClick={() => setTab(id)}
                  onKeyDown={onTabKeyDown}
                  className={`flex items-center justify-center gap-2 rounded-md px-3 py-2.5 text-sm font-medium cursor-pointer transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                    tab === id ? 'bg-raised text-ink shadow-sm' : 'text-ink-muted hover:text-ink'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </button>
              ))}
            </div>

            <form id="panel-input" role="tabpanel" aria-labelledby={`tab-${tab}`} onSubmit={submit} className="space-y-4">
              {tab === 'url' ? (
                <div>
                  <label htmlFor="url-input" className="block text-sm font-medium text-ink mb-1.5">URL to check</label>
                  <input
                    id="url-input"
                    type="text"
                    inputMode="url"
                    autoComplete="off"
                    spellCheck={false}
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="https://example.com/login"
                    aria-describedby="url-help"
                    className="w-full rounded-lg border border-line bg-canvas px-3.5 py-2.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/40"
                  />
                  <p id="url-help" className="mt-1.5 text-xs text-ink-muted">
                    The http:// or https:// prefix is ignored, matching how the model was trained.
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <label htmlFor="email-input" className="block text-sm font-medium text-ink mb-1.5">Email content</label>
                    <textarea
                      id="email-input"
                      value={emailText}
                      onChange={e => setEmailText(e.target.value)}
                      placeholder="Paste the full email, including headers and links"
                      rows={8}
                      aria-describedby="email-help"
                      className="w-full resize-y rounded-lg border border-line bg-canvas px-3.5 py-3 text-sm text-ink placeholder:text-ink-faint focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/40"
                    />
                    <p id="email-help" className="mt-1.5 text-xs text-ink-muted">
                      Every link in the email is extracted and scored on its own.
                    </p>
                  </div>
                  <div className="flex items-start justify-between gap-4 rounded-lg border border-line bg-canvas px-3.5 py-3">
                    <div>
                      <span id="privacy-label" className="flex items-center gap-2 text-sm font-medium text-ink">
                        <LockIcon className="w-4 h-4 text-ink-muted" />
                        Zero-retention mode
                      </span>
                      <span id="privacy-desc" className="mt-0.5 block text-xs text-ink-muted">
                        Email content is processed in memory and never logged.
                      </span>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={privacyMode}
                      aria-labelledby="privacy-label"
                      aria-describedby="privacy-desc"
                      onClick={() => setPrivacyMode(v => !v)}
                      className={`relative flex-none mt-0.5 w-11 h-6 rounded-full cursor-pointer transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-canvas ${
                        privacyMode ? 'bg-accent-solid' : 'bg-line'
                      }`}
                    >
                      <span
                        className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform duration-200 ${privacyMode ? 'translate-x-5' : ''}`}
                      />
                    </button>
                  </div>
                </>
              )}

              <button
                type="submit"
                disabled={!input.trim() || isLoading}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-accent-solid px-5 py-2.5 text-sm font-semibold text-white cursor-pointer transition-colors duration-200 hover:bg-accent-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isLoading && <SpinnerIcon />}
                {isLoading ? 'Analyzing' : tab === 'url' ? 'Analyze URL' : 'Scan email'}
              </button>
            </form>

            <div className="mt-6 pt-5 border-t border-line">
              <p className="text-xs font-medium text-ink-muted mb-2">Try a sample</p>
              <div className="flex flex-wrap gap-2">
                {SAMPLES[tab].map(s => (
                  <button
                    key={s.label}
                    type="button"
                    onClick={() => runSample(s.value)}
                    disabled={isLoading}
                    className="rounded-full border border-line px-3 py-1.5 text-xs text-ink cursor-pointer transition-colors duration-200 hover:border-accent hover:bg-raised focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          </section>

          {/* Results panel */}
          <section
            aria-live="polite"
            aria-busy={isLoading}
            aria-label="Analysis result"
            className="lg:col-span-7 rounded-xl border border-line bg-surface p-5 sm:p-6 min-h-[18rem]"
          >
            {error ? (
              <div role="alert" className="flex items-start gap-3 rounded-lg border border-status-critical/50 bg-status-critical/10 p-4">
                <AlertCircleIcon className="w-5 h-5 flex-none text-status-critical" />
                <div>
                  <p className="text-sm font-medium text-ink">Analysis failed</p>
                  <p className="mt-0.5 text-sm text-ink-muted">{error}</p>
                </div>
              </div>
            ) : result ? (
              tab === 'url'
                ? <UrlResult data={result.data} />
                : <EmailResult data={result.data} privacyMode={result.privacyMode} />
            ) : (
              <div className="h-full min-h-[15rem] grid place-items-center text-center">
                <div className="max-w-sm">
                  <span className="mx-auto mb-4 grid place-items-center w-12 h-12 rounded-xl bg-raised text-ink-muted">
                    <ShieldIcon className="w-6 h-6" />
                  </span>
                  <p className="text-sm font-medium text-ink">No analysis yet</p>
                  <p className="mt-1 text-sm text-ink-muted">
                    {tab === 'url'
                      ? 'Enter a URL or pick a sample. The result shows the phishing probability and the tokens behind it.'
                      : 'Paste an email or pick a sample. Each link is scored and the email gets an overall verdict.'}
                  </p>
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Model section */}
        <section className="mt-16" aria-labelledby="model-heading">
          <h2 id="model-heading" className="text-2xl font-semibold tracking-tight text-ink">How the model works</h2>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-ink-muted">
            Trained in <span className="font-mono text-ink">modetSetup.ipynb</span> on the Kaggle phishing site URLs
            dataset after removing duplicate URLs, with an 80/20 stratified train and test split.
          </p>

          <ol className="mt-6 grid gap-4 md:grid-cols-3">
            {PIPELINE.map(p => (
              <li key={p.step} className="rounded-xl border border-line bg-surface p-5">
                <span className="font-mono text-xs text-accent">{p.step}</span>
                <h3 className="mt-2 text-base font-semibold text-ink">{p.title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-ink-muted">{p.body}</p>
              </li>
            ))}
          </ol>

          <dl className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
            {MODEL_METRICS.map(m => (
              <div key={m.label} className="rounded-xl border border-line bg-surface p-5">
                <dt className="text-sm text-ink-muted">{m.label}</dt>
                <dd className="mt-1 text-2xl font-semibold text-ink">{m.value}</dd>
              </div>
            ))}
          </dl>

          <div className="mt-4 rounded-xl border border-line bg-surface p-5">
            <h3 className="text-sm font-semibold text-ink">Known limitations</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-ink-muted">
              The model only sees the words in a URL, not the page content or the domain's reputation. Words that
              are common in phishing kits, such as <span className="font-mono text-ink">login</span>,{' '}
              <span className="font-mono text-ink">mail</span> and <span className="font-mono text-ink">paypal</span>,
              can flag legitimate pages like <span className="font-mono text-ink">github.com/login</span>. A short
              list of trusted domains catches the most common of these; everything else is scored by the model.
              Treat a result as one signal, not a final answer.
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 flex flex-col sm:flex-row gap-2 justify-between text-xs text-ink-muted">
          <span>Built by Daniel Cornett</span>
          <span>Logistic regression · CountVectorizer · FastAPI · React</span>
        </div>
      </footer>
    </div>
  );
}
