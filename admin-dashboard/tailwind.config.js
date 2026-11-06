/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#070B14",
          sidebar: "#0C1322",
          card: "#111A2E",
          cardLight: "#18243D",
          border: "#1E2D4A",
          primary: "#3B82F6",
          accent: "#60A5FA",
          danger: "#EF4444",
          warning: "#F59E0B",
          safe: "#10B981"
        }
      }
    },
  },
  plugins: [],
}

