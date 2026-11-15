// Serves the stand-in Gmail page for browser tests. Nothing else is served.
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const page = resolve(dirname(fileURLToPath(import.meta.url)), "fake-gmail.html");

createServer(async (request, response) => {
  const { pathname } = new URL(request.url ?? "/", "http://localhost");
  if (pathname !== "/" && pathname !== "/mail") {
    response.writeHead(404).end("Not found");
    return;
  }
  response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  response.end(await readFile(page));
}).listen(4173, "127.0.0.1", () => console.log("Stand-in Gmail page on http://localhost:4173"));
