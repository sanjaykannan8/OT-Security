// Offline build: bundles React + app into dist/app.js; no CDN, fonts or runtime fetches.
// Every asset the page references is copied here, because the API serves dist/ as-is under
// a CSP of default-src 'self' - anything not present locally simply will not load.
import { build } from "esbuild";
import { cpSync, mkdirSync } from "node:fs";

mkdirSync("dist/fonts", { recursive: true });
await build({
  entryPoints: ["src/main.tsx"],
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2020",
  outfile: "dist/app.js",
  jsx: "automatic",
  legalComments: "none",
  define: { "process.env.NODE_ENV": '"production"' },
});
cpSync("index.html", "dist/index.html");
cpSync("src/styles.css", "dist/styles.css");
cpSync("favicon.svg", "dist/favicon.svg");
// Variable weight axis 200-800, latin subset only: one file covers every weight the UI uses.
cpSync(
  "node_modules/@fontsource-variable/plus-jakarta-sans/files/plus-jakarta-sans-latin-wght-normal.woff2",
  "dist/fonts/plus-jakarta-sans.woff2",
);
console.log("built dist/");
