import type { Config } from "tailwindcss";
import forms from "@tailwindcss/forms";

const config: Config = {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Manrope", "system-ui", "sans-serif"],
        display: ["Space Grotesk", "Manrope", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      colors: {
        shell: "#f4f7f5",
        slate: {
          950: "#0c1b1a",
          900: "#12302f",
          800: "#184140",
          700: "#225957",
          500: "#3d8d89",
          300: "#8cc9c4",
          100: "#d8efed",
        },
        ember: {
          500: "#ef7d38",
          300: "#f8b27f",
          100: "#fce7d8",
        },
      },
      boxShadow: {
        soft: "0 12px 40px rgba(16, 34, 33, 0.08)",
        panel: "0 20px 60px rgba(12, 27, 26, 0.14)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulsebar: {
          "0%, 100%": { opacity: "0.8" },
          "50%": { opacity: "1" },
        },
      },
      animation: {
        "fade-up": "fade-up 420ms ease-out both",
        pulsebar: "pulsebar 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [forms],
};

export default config;
