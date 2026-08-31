/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0b0f17',
          panel: '#111827',
          panel2: '#0f172a',
          border: '#1f2937',
          text: '#e5e7eb',
          muted: '#9ca3af',
          accent: '#22d3ee',
          danger: '#f43f5e',
          warn: '#f59e0b',
          good: '#10b981',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
