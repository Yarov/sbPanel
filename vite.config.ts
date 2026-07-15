import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En build (GitHub Pages) la app vive bajo /sbPanel/. En dev, en la raíz.
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/sbPanel/" : "/",
  plugins: [react()],
}));
