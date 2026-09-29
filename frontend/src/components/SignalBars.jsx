import React from 'react';

const PHISH = '#e66767';
const SAFE  = '#3987e5';

const Swatch = ({ color, label }) => (
  <span className="inline-flex items-center gap-1.5">
    <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} aria-hidden="true" />
    {label}
  </span>
);

// Diverging bar list: each token's weight (count x model coefficient) around a neutral zero line
export default function SignalBars({ signals, trusted = false }) {
  if (trusted) {
    return (
      <p className="text-sm text-ink-muted">
        This domain is on the trusted domain list, so it is marked safe without running the model. The list
        covers well-known sites that the word-based model can misread, such as github.com/login.
      </p>
    );
  }

  if (!signals.length) {
    return (
      <p className="text-sm text-ink-muted">
        None of this URL's tokens appear in the model's vocabulary, so the prediction comes from the
        model's baseline alone.
      </p>
    );
  }

  const maxAbs = Math.max(...signals.map(s => Math.abs(s.weight)), 1);

  return (
    <figure>
      <figcaption className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 mb-3">
        <span className="text-sm font-medium text-ink">What drove this result</span>
        <span className="flex gap-4 text-xs text-ink-muted">
          <Swatch color={SAFE} label="Toward legitimate" />
          <Swatch color={PHISH} label="Toward phishing" />
        </span>
      </figcaption>

      <ul className="space-y-1">
        {signals.map(({ token, weight }) => {
          const width = `${(Math.abs(weight) / maxAbs) * 50}%`;
          const toPhish = weight > 0;
          const direction = toPhish ? 'toward phishing' : 'toward legitimate';
          return (
            <li
              key={token}
              title={`"${token}" pushes ${direction} (${weight > 0 ? '+' : ''}${weight.toFixed(2)})`}
              className="grid grid-cols-[minmax(4rem,7rem)_1fr_3.5rem] items-center gap-3 rounded px-1 py-1 hover:bg-raised"
            >
              <span className="font-mono text-xs text-ink truncate">{token}</span>
              <span className="relative h-2.5" aria-hidden="true">
                <span className="absolute left-1/2 -top-1 -bottom-1 w-px bg-line" />
                <span
                  className={`absolute top-0 h-full ${toPhish ? 'left-1/2 rounded-r' : 'right-1/2 rounded-l'}`}
                  style={{ width, backgroundColor: toPhish ? PHISH : SAFE }}
                />
              </span>
              <span className="text-right text-xs tabular-nums text-ink-muted">
                <span className="sr-only">{direction} </span>
                {weight > 0 ? '+' : ''}{weight.toFixed(2)}
              </span>
            </li>
          );
        })}
      </ul>
      <p className="mt-3 text-xs text-ink-faint">
        Tokens are stemmed words from the URL (for example "verifi" for "verify"). Weight is the token
        count multiplied by the model's learned coefficient.
      </p>
    </figure>
  );
}
