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
        canvas: '#000000', // OLED Pure Black Canvas
        surface: {
          base: '#0c0c0f',
          elevated: '#141418',
          hover: '#1e1e24',
          code: '#0d0d12',
        },
        border: {
          DEFAULT: '#1e1e24',
          subtle: '#141418',
          strong: '#2a2a34',
        },
        accent: {
          primary: '#b39aff',      // Dark Theme Lavender (Primary - 10.2:1 AAA on #000000)
          dark: '#9a79ff',         // Hover state
          darker: '#8059f5',       // Active pressed
          darkest: '#501ee8',      // Deep outline
          glow: '#cbbafe',         // Interactive glow
          lighter: '#dbceff',      // Monospace badge
          lightest: '#f1ecfe',     // Text tint
          soft: 'rgba(124, 58, 237, 0.09)', // Specialized accent tint
          lavender: '#d8ccff',     // Inline code tint (13.5:1 on #000000)
          violet: '#7c3aed',       // Violet accent
          royal: '#6d28d9',        // Royal Violet
          secondary: '#7c3aed',
        },
        brand: {
          title: '#f5f3ff',        // Crisp lavender-tinted white
          body: '#d2d0dc',         // High-legibility neutral body
          muted: '#9696a4',        // Secondary meta & labels
        },
        status: {
          healthy: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      borderRadius: {
        sm: '0.35rem',
        md: '0.55rem',
        lg: '0.65rem',
        xl: '1.25rem',
      },
      transitionDuration: {
        DEFAULT: '160ms',
      },
    },
  },
  plugins: [],
}
