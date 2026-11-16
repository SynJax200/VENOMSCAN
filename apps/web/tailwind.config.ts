import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Jet Black canvas with light typography (moodboard theme).
        ink: "#F4F4F6",
        surface: "#0A0A0A",
        panel: "#121216",
        line: "#26262D",
        muted: "#8B8B95",
        brand: {
          DEFAULT: "#0078A7",
          hover: "#0092C9",
          soft: "#0A2632",
          ring: "#2FB4E0",
        },
        accent: {
          DEFAULT: "#B71095",
          hover: "#D316AF",
          soft: "#2A0A24",
        },
        severity: {
          critical: "#FF3B5C",
          high: "#FF8A3D",
          medium: "#FFC53D",
          low: "#33B5FF",
          info: "#8B8B95",
        },
        // Inverted slate ramp so existing text/border utilities stay legible on black.
        slate: {
          50: "#141418",
          100: "#1B1B21",
          200: "#26262D",
          300: "#4A4A54",
          400: "#70707B",
          500: "#90909B",
          600: "#B2B2BC",
          700: "#CACAD2",
          800: "#E4E4EA",
          900: "#F4F4F6",
        },
      },
      borderRadius: {
        card: "12px",
      },
      boxShadow: {
        card: "0 1px 0 rgba(255, 255, 255, 0.04) inset, 0 12px 32px rgba(0, 0, 0, 0.45)",
        pop: "0 24px 64px rgba(0, 0, 0, 0.65)",
        glow: "0 0 0 1px rgba(183, 16, 149, 0.35), 0 8px 32px rgba(183, 16, 149, 0.22)",
      },
      fontFamily: {
        sans: [
          "Inter",
          "Segoe UI",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "SFMono-Regular", "Consolas", "monospace"],
      },
      keyframes: {
        "fade-up": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        pulseSoft: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.45" },
        },
      },
      animation: {
        "fade-up": "fade-up 240ms ease-out",
        "pulse-soft": "pulseSoft 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
