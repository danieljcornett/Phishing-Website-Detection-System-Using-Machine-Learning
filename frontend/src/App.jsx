import React, { useState } from 'react';

const API_BASE = 'http://localhost:8000';

const VERDICT_STYLES = {
  PHISHING:   { bg: 'bg-red-100',    border: 'border-red-500',    text: 'text-red-700',    icon: '🚨' },
  SUSPICIOUS: { bg: 'bg-yellow-100', border: 'border-yellow-500', text: 'text-yellow-700', icon: '⚠️' },
  SAFE:       { bg: 'bg-green-100',  border: 'border-green-500',  text: 'text-green-700',  icon: '✅' },
};

const RISK_BADGE = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-400 text-black',
  LOW:      'bg-green-500 text-white',
};

const ConfidenceBar = ({ value }) => {
  const pct = Math.round(value * 100);
  const color = pct >= 85 ? 'bg-red-500' : pct >= 50 ? 'bg-yellow-400' : 'bg-green-500';
  return (
    <div className="w-full bg-gray-200 rounded-full h-2.5 mt-1">
      <div className={`${color} h-2.5 rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
    </div>
  );
};

export default function App() {
  const [tab, setTab] = useState('url');
  const [url, setUrl] = useState('');
  const [emailText, setEmailText] = useState('');
  const [privacyMode, setPrivacyMode] = useState(true);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeUrl = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      setResult({ type: 'url', data });
    } catch (e) {
      setError('Could not reach the API. Make sure uvicorn is running on port 8000.');
    }
    setLoading(false);
  };

  const analyzeEmail = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: emailText, privacy_mode: privacyMode }),
      });
      const data = await res.json();
      setResult({ type: 'email', data });
    } catch (e) {
      setError('Could not reach the API. Make sure uvicorn is running on port 8000.');
    }
    setLoading(false);
  };

  const urlVerdict = result?.type === 'url'
    ? (result.data.is_phishing ? (result.data.confidence >= 0.85 ? 'PHISHING' : 'SUSPICIOUS') : 'SAFE')
    : null;

  const emailVerdict = result?.type === 'email' ? result.data.overall_verdict : null;
  const activeVerdict = urlVerdict || emailVerdict;
  const style = activeVerdict ? VERDICT_STYLES[activeVerdict] : null;

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center gap-3">
        <span className="text-2xl">🛡️</span>
        <div>
          <h1 className="text-xl font-bold tracking-tight">Anti-Phishing Detection System</h1>
          <p className="text-xs text-gray-400">ML-powered threat analysis</p>
        </div>
      </header>

      <main className="flex-1 max-w-3xl mx-auto w-full px-4 py-10">
        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => { setTab('url'); setResult(null); setError(null); }}
            className={`px-5 py-2 rounded-full text-sm font-semibold transition ${tab === 'url' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            🔗 Check URL
          </button>
          <button
            onClick={() => { setTab('email'); setResult(null); setError(null); }}
            className={`px-5 py-2 rounded-full text-sm font-semibold transition ${tab === 'email' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            📧 Scan Email
          </button>
        </div>

        {/* URL Tab */}
        {tab === 'url' && (
          <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
            <h2 className="text-lg font-semibold mb-4">Check a Single URL</h2>
            <div className="flex gap-3">
              <input
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && analyzeUrl()}
                placeholder="https://example.com/login"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={analyzeUrl}
                disabled={!url || loading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-5 py-2.5 rounded-lg text-sm font-semibold transition"
              >
                {loading ? 'Analyzing...' : 'Analyze'}
              </button>
            </div>

            {/* URL Result */}
            {result?.type === 'url' && style && (
              <div className={`mt-6 rounded-xl border-2 ${style.border} ${style.bg} p-5`}>
                <div className={`flex items-center gap-2 text-xl font-bold ${style.text} mb-2`}>
                  <span>{style.icon}</span>
                  <span>{activeVerdict}</span>
                  <span className={`ml-auto text-xs px-2 py-1 rounded-full font-bold ${RISK_BADGE[result.data.risk_level]}`}>
                    {result.data.risk_level}
                  </span>
                </div>
                <p className={`text-sm ${style.text} mb-3`}>{result.data.message}</p>
                <div className="text-sm text-gray-700">
                  <div className="flex justify-between mb-1">
                    <span>Phishing Confidence</span>
                    <span className="font-bold">{Math.round(result.data.confidence * 100)}%</span>
                  </div>
                  <ConfidenceBar value={result.data.confidence} />
                </div>
                <p className="text-xs text-gray-500 mt-3 break-all">URL: {result.data.url}</p>
              </div>
            )}
          </div>
        )}

        {/* Email Tab */}
        {tab === 'email' && (
          <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
            <h2 className="text-lg font-semibold mb-4">Scan Email for Phishing URLs</h2>
            <textarea
              value={emailText}
              onChange={e => setEmailText(e.target.value)}
              placeholder="Paste the full email body here, including any links..."
              rows={8}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-blue-500 resize-none"
            />
            <div className="flex items-center justify-between mt-3 mb-4">
              <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={privacyMode}
                  onChange={e => setPrivacyMode(e.target.checked)}
                  className="w-4 h-4 accent-blue-500"
                />
                🔒 Zero-Retention Privacy Mode
              </label>
              <button
                onClick={analyzeEmail}
                disabled={!emailText || loading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-5 py-2.5 rounded-lg text-sm font-semibold transition"
              >
                {loading ? 'Scanning...' : 'Scan Email'}
              </button>
            </div>

            {/* Email Result */}
            {result?.type === 'email' && style && (
              <div className={`rounded-xl border-2 ${style.border} ${style.bg} p-5`}>
                <div className={`flex items-center gap-2 text-xl font-bold ${style.text} mb-2`}>
                  <span>{style.icon}</span>
                  <span>{emailVerdict}</span>
                </div>
                <p className={`text-sm ${style.text} mb-4`}>{result.data.warning_message}</p>

                {result.data.url_results?.length > 0 && (
                  <div>
                    <p className="text-xs font-bold text-gray-600 uppercase mb-2">URLs Found ({result.data.urls_found})</p>
                    <div className="space-y-3">
                      {result.data.url_results.map((u, i) => (
                        <div key={i} className="bg-white bg-opacity-60 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-mono text-gray-700 truncate max-w-xs">{u.url}</span>
                            <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${RISK_BADGE[u.risk_level]}`}>
                              {u.risk_level}
                            </span>
                          </div>
                          <div className="flex justify-between text-xs text-gray-600 mb-1">
                            <span>{u.is_phishing ? '⚠️ Phishing' : '✅ Safe'}</span>
                            <span>{Math.round(u.confidence * 100)}% confidence</span>
                          </div>
                          <ConfidenceBar value={u.confidence} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="mt-4 bg-red-900 border border-red-700 text-red-200 rounded-xl p-4 text-sm">
            ❌ {error}
          </div>
        )}

        {/* Sample inputs */}
        <div className="mt-8 bg-gray-900 rounded-2xl p-5 border border-gray-800">
          <p className="text-xs font-bold text-gray-400 uppercase mb-3">Quick Demo Samples</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              { label: '✅ Legit', value: 'https://github.com', type: 'url' },
              { label: '🚨 Suspicious', value: 'http://paypal-secure-login.verify-account.xyz', type: 'url' },
              { label: '✅ Safe Email', value: 'Hi, check out our docs at https://docs.github.com for help.', type: 'email' },
              { label: '🚨 Phishing Email', value: 'URGENT: Your account is suspended. Verify now at http://paypal-login.free-site.ru or lose access permanently.', type: 'email' },
            ].map((s, i) => (
              <button
                key={i}
                onClick={() => {
                  if (s.type === 'url') { setTab('url'); setUrl(s.value); setResult(null); }
                  else { setTab('email'); setEmailText(s.value); setResult(null); }
                }}
                className="text-left text-xs bg-gray-800 hover:bg-gray-700 rounded-lg px-3 py-2 transition"
              >
                <span className="font-semibold">{s.label}</span>
                <p className="text-gray-400 truncate mt-0.5">{s.value}</p>
              </button>
            ))}
          </div>
        </div>
      </main>

      <footer className="text-center text-xs text-gray-600 py-4">
        Built by Daniel Cornett · Anti-Phishing Detection System
      </footer>
    </div>
  );
}
