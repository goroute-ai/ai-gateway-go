/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: '#090D16',
        surface: {
          base: '#0F172A',
          elevated: '#1E293B',
          hover: '#334155',
        },
        border: {
          subtle: 'rgba(255, 255, 255, 0.06)',
          strong: 'rgba(255, 255, 255, 0.12)',
        },
        accent: {
          primary: '#06B6D4',
          glow: '#22D3EE',
          secondary: '#6366F1',
        },
        status: {
          healthy: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
