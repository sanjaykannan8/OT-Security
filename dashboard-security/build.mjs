// Offline build: bundles React + app into dist/app.js; no CDN, fonts or runtime fetches.
import { build } from "esbuild";
import { cpSync, mkdirSync } from "node:fs";

mkdirSync("dist", { recursive: true });
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
console.log("built dist/");
