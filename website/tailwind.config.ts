import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{ts,tsx,mdx}',
    './components/**/*.{ts,tsx}',
    './content/**/*.mdx',
    './node_modules/fumadocs-ui/dist/**/*.js',
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ['var(--font-syne)', 'sans-serif'],
        mono: ['var(--font-jetbrains)', 'JetBrains Mono', 'monospace'],
        sans: ['var(--font-geist)', 'system-ui', 'sans-serif'],
      },
      colors: {
        attack: {
          50: '#fff1f1',
          100: '#ffe1e1',
          200: '#ffc7c7',
          300: '#ffa0a0',
          400: '#ff6b6b',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
          DEFAULT: '#ef4444',
        },
        safe: {
          DEFAULT: '#22d3ee',
          dim: '#0891b2',
        },
        node: {
          DEFAULT: '#a3e635',
          dim: '#65a30d',
        },
        surface: {
          950: '#020609',
          900: '#050a0e',
          800: '#090f15',
          700: '#0f1923',
          600: '#162030',
          500: '#1e2d40',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 4s linear infinite',
        'float': 'float 6s ease-in-out infinite',
        'path': 'drawPath 2s ease-in-out infinite alternate',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' },
        },
        glow: {
          '0%': { textShadow: '0 0 10px rgba(239,68,68,0.3)' },
          '100%': { textShadow: '0 0 30px rgba(239,68,68,0.8), 0 0 60px rgba(239,68,68,0.4)' },
        },
      },
      backgroundImage: {
        'grid-pattern': `linear-gradient(rgba(34, 211, 238, 0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(34, 211, 238, 0.04) 1px, transparent 1px)`,
        'hex-pattern': `radial-gradient(circle at 25% 25%, rgba(239,68,68,0.06) 0%, transparent 50%),
          radial-gradient(circle at 75% 75%, rgba(34,211,238,0.06) 0%, transparent 50%)`,
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
    },
  },
};

export default config;