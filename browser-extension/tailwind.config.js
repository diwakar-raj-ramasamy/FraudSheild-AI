/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,html}",
    "./*.html"
  ],
  theme: {
    extend: {
      colors: {
        shield: {
          bg: "#0B0F19",
          card: "#111827",
          border: "#1F2937",
          primary: "#3B82F6",
          danger: "#EF4444",
          warning: "#F59E0B",
          safe: "#10B981"
        }
      }
    },
  },
  plugins: [],
}

