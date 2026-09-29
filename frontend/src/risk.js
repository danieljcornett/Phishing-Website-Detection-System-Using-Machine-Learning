// Status colors mirror tailwind.config.js; every use pairs the color with an icon or a text label
export const RISK = {
  LOW:      { label: 'Low risk',      color: '#0ca30c' },
  MEDIUM:   { label: 'Medium risk',   color: '#fab219' },
  HIGH:     { label: 'High risk',     color: '#ec835a' },
  CRITICAL: { label: 'Critical risk', color: '#d03b3b' },
};

export const VERDICT = {
  SAFE:       { label: 'Likely legitimate', color: '#0ca30c' },
  SUSPICIOUS: { label: 'Suspicious',        color: '#fab219' },
  PHISHING:   { label: 'Likely phishing',   color: '#d03b3b' },
};
