const withOpacity = (varName) => `rgb(var(${varName}) / <alpha-value>)`;

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
        canvas: withOpacity('--rgb-canvas'),
        surface: {
          base: withOpacity('--rgb-surface-base'),
          elevated: withOpacity('--rgb-surface-elevated'),
          hover: withOpacity('--rgb-surface-hover'),
          code: withOpacity('--rgb-surface-code'),
          input: withOpacity('--rgb-surface-input'),
        },
        border: {
          DEFAULT: withOpacity('--rgb-border'),
          subtle: withOpacity('--rgb-border-subtle'),
          strong: withOpacity('--rgb-border-strong'),
        },
        accent: {
          primary: withOpacity('--rgb-accent-primary'),
          dark: withOpacity('--rgb-accent-dark'),
          darker: withOpacity('--rgb-accent-darker'),
          darkest: withOpacity('--rgb-accent-darker'),
          glow: withOpacity('--rgb-accent-glow'),
          light: withOpacity('--rgb-accent-glow'),
          lighter: withOpacity('--rgb-accent-lighter'),
          lightest: withOpacity('--rgb-accent-lighter'),
          contrast: withOpacity('--rgb-accent-contrast'),
          soft: 'var(--accent-soft)',
          secondary: withOpacity('--rgb-accent-dark'),
        },
        brand: {
          title: withOpacity('--rgb-text-title'),
          body: withOpacity('--rgb-text-body'),
          muted: withOpacity('--rgb-text-muted'),
        },
        status: {
          healthy: withOpacity('--rgb-status-success'),
          success: withOpacity('--rgb-status-success'),
          warning: withOpacity('--rgb-status-warning'),
          danger: withOpacity('--rgb-status-danger'),
          info: withOpacity('--rgb-status-info'),
        },
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
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
};
