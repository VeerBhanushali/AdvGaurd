import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#eefcf3",
          100: "#d7f7e2",
          500: "#2db365",
          600: "#229451",
          700: "#1d7542",
        },
      },
    },
  },
  plugins: [],
};
export default config;

