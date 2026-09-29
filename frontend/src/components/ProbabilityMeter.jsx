import React from 'react';
import { RISK } from '../risk';

// Fill carries severity; the track is a faint step of the same color so state reads across the bar
export default function ProbabilityMeter({ value, riskLevel, compact = false }) {
  const pct = Math.round(value * 1000) / 10;
  const color = RISK[riskLevel].color;

  return (
    <div>
      {!compact && (
        <div className="flex items-baseline justify-between mb-2">
          <span className="text-sm text-ink-muted">Phishing probability</span>
          <span className="text-lg font-semibold text-ink">{pct}%</span>
        </div>
      )}
      <div
        role="meter"
        aria-label="Phishing probability"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-valuetext={`${pct}% probability of phishing, ${RISK[riskLevel].label.toLowerCase()}`}
        className="relative h-2.5 rounded"
        style={{ backgroundColor: `${color}33` }}
      >
        <div
          className="h-full rounded-r motion-safe:transition-[width] motion-safe:duration-500 motion-safe:ease-out"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
        {/* Decision threshold: the model labels a URL as phishing at 50% */}
        <div className="absolute left-1/2 -top-1 -bottom-1 w-0.5 -translate-x-1/2 bg-ink-muted" />
      </div>
      {!compact && (
        <div className="relative mt-1.5 h-4 text-xs text-ink-faint">
          <span className="absolute left-0">0%</span>
          <span className="absolute left-1/2 -translate-x-1/2 whitespace-nowrap">50% threshold</span>
          <span className="absolute right-0">100%</span>
        </div>
      )}
    </div>
  );
}
