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
        background: "#030712", // Very dark navy/black
        surface: "#0f172a",    // Slate-900 for cards
        border: "#1e293b",     // Slate-800 for thin borders
        accent: "#3b82f6",     // Blue
        success: "#10b981",    // Emerald green
        warning: "#f59e0b",    // Amber orange
        danger: "#ef4444",     // Red
        muted: "#64748b",      // Slate-500
      },
    },
  },
  plugins: [],
}
