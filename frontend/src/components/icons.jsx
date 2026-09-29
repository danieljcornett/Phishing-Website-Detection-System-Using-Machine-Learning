import React from 'react';

// Stroke icons (Lucide geometry), decorative by default
const Icon = ({ className = 'w-5 h-5', children, ...props }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
    className={className}
    {...props}
  >
    {children}
  </svg>
);

const SHIELD = 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z';

export const ShieldIcon = (p) => (
  <Icon {...p}><path d={SHIELD} /></Icon>
);

export const ShieldCheckIcon = (p) => (
  <Icon {...p}><path d={SHIELD} /><path d="m9 12 2 2 4-4" /></Icon>
);

export const ShieldAlertIcon = (p) => (
  <Icon {...p}><path d={SHIELD} /><path d="M12 8v4" /><path d="M12 16h.01" /></Icon>
);

export const ShieldXIcon = (p) => (
  <Icon {...p}><path d={SHIELD} /><path d="m14.5 9.5-5 5" /><path d="m9.5 9.5 5 5" /></Icon>
);

export const LinkIcon = (p) => (
  <Icon {...p}>
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
  </Icon>
);

export const MailIcon = (p) => (
  <Icon {...p}>
    <rect width="20" height="16" x="2" y="4" rx="2" />
    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </Icon>
);

export const LockIcon = (p) => (
  <Icon {...p}>
    <rect width="18" height="11" x="3" y="11" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </Icon>
);

export const AlertCircleIcon = (p) => (
  <Icon {...p}><circle cx="12" cy="12" r="10" /><path d="M12 8v4" /><path d="M12 16h.01" /></Icon>
);

export const ChevronDownIcon = (p) => (
  <Icon {...p}><path d="m6 9 6 6 6-6" /></Icon>
);

export const SpinnerIcon = ({ className = 'w-4 h-4', ...p }) => (
  <Icon className={`${className} motion-safe:animate-spin`} {...p}>
    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
  </Icon>
);
