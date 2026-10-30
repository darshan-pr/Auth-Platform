import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";

const packageName = process.argv[2];
if (!packageName) throw new Error("Package name is required");
const root = resolve(new URL("..", import.meta.url).pathname);
const packageDir = resolve(root, "packages", packageName);
const typescript = resolve(root, "node_modules", "typescript", "bin", "tsc");
const esbuild = resolve(root, "node_modules", "esbuild", "bin", "esbuild");

await rm(resolve(packageDir, "dist"), { recursive: true, force: true });
await mkdir(resolve(packageDir, "dist", "types"), { recursive: true });
const common = ["-p", resolve(packageDir, "tsconfig.json"), "--rootDir", resolve(packageDir, "src"), "--noEmit", "false"];
execFileSync(process.execPath, [typescript, ...common, "--declaration", "--emitDeclarationOnly", "--outDir", resolve(packageDir, "dist", "types")], { stdio: "inherit" });
execFileSync(process.execPath, [typescript, ...common, "--declaration", "false", "--module", "ES2022", "--moduleResolution", "Bundler", "--outDir", resolve(packageDir, "dist", "esm")], { stdio: "inherit" });
execFileSync(process.execPath, [typescript, ...common, "--declaration", "false", "--module", "CommonJS", "--moduleResolution", "Node", "--outDir", resolve(packageDir, "dist", "cjs")], { stdio: "inherit" });
const external = packageName === "auth-react"
  ? ["react", "react/*", "@authplatform/auth-core"]
  : packageName === "auth-nextjs"
    ? ["next", "next/*", "server-only", "@authplatform/auth-core"]
    : [];
for (const format of ["esm", "cjs"]) {
  const outputDir = resolve(packageDir, "dist", format);
  const entries = (await readdir(outputDir)).filter((file) => file.endsWith(".js"));
  for (const file of entries) {
    const entry = resolve(outputDir, file);
    execFileSync(esbuild, [entry, "--bundle", "--minify", "--legal-comments=none", "--allow-overwrite", "--log-override:commonjs-variable-in-esm=silent", `--format=${format}`, `--outfile=${entry}`, ...external.map((name) => `--external:${name}`)], { stdio: "inherit" });
  }
}
if (packageName === "auth-react") await cp(resolve(packageDir, "src", "styles.css"), resolve(packageDir, "dist", "styles.css"));
await cp(resolve(packageDir, "package.json"), resolve(packageDir, "dist", "package.json"));
await import("node:fs/promises").then(({ writeFile }) => writeFile(resolve(packageDir, "dist", "cjs", "package.json"), '{"type":"commonjs"}\n'));
