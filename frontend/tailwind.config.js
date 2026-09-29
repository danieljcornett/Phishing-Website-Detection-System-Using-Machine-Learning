// tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      colors: {
        canvas:  '#0b0f17',
        surface: '#111827',
        raised:  '#1a2233',
        line:    '#263043',
        ink: {
          DEFAULT: '#e6e9ef',
          muted:   '#9aa4b5',
          faint:   '#8590a3',
        },
        accent: {
          DEFAULT: '#3987e5',   // focus rings, icons, links
          solid:   '#2563c9',   // button fill (white text 5.7:1)
          hover:   '#1f5bb8',
        },
        // Status colors: always paired with an icon and a text label
        status: {
          good:     '#0ca30c',
          warning:  '#fab219',
          serious:  '#ec835a',
          critical: '#d03b3b',
        },
        // Diverging pair for model signals
        toward: {
          safe:  '#3987e5',
          phish: '#e66767',
        },
      },
    },
  },
  plugins: [],
}
