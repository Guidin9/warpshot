// PC → phone wake-ups in the emulator without Firebase (docs/dev-setup.md
// section 9). Starts the local `wrangler dev` server with FCM pointed at a fake
// FCM host on 127.0.0.1 and a throwaway service-account key, and forwards each
// push message's wake envelope to the emulator's debug-only DemoActivity
// (`--es wake`), which hands it to TransferService as a real push would.
// The phone registers a fake push token with `--es push_token` (printed below).
//   node scripts/fake-fcm.mjs <work dir>        (runs until stopped; use with test-pc.mjs)
// Logs (wrangler.log, fcm.log) carry no envelopes or tokens.
import { execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
if (!process.argv[2]) {
  console.error("usage: node scripts/fake-fcm.mjs <work dir>");
  process.exit(2);
}
const work = path.resolve(process.argv[2]);
fs.mkdirSync(work, { recursive: true });
const FCM_PORT = 8788;
const SERVER_PORT = 8787;
const adb = path.join(process.env.LOCALAPPDATA ?? "", "Android", "Sdk", "platform-tools", "adb.exe");
const log = (s) => fs.appendFileSync(path.join(work, "fcm.log"), `${new Date().toISOString()} ${s}\n`);

// Throwaway key: the server signs its OAuth assertion with it; the fake ignores the signature.
const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const sa = {
  type: "service_account",
  project_id: "emu-test",
  client_email: "fake@emu-test.iam.gserviceaccount.com",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
};
const envFile = path.join(work, "fcm.env");
fs.writeFileSync(envFile, `FCM_SERVICE_ACCOUNT='${JSON.stringify(sa)}'\nFCM_BASE_URL=http://127.0.0.1:${FCM_PORT}\n`);

const fake = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/token") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "fake", expires_in: 3600 }));
      return;
    }
    if (req.method === "POST" && /^\/v1\/projects\/[^/]+\/messages:send$/.test(req.url ?? "")) {
      let e;
      try {
        e = JSON.parse(body).message.data.e;
      } catch {
        e = undefined;
      }
      if (typeof e !== "string" || !/^[A-Za-z0-9_-]+$/.test(e)) {
        log("push: malformed");
        res.writeHead(400).end();
        return;
      }
      try {
        execFileSync(adb, ["shell", "am", "start", "-n", "io.github.guidin9.warpshot/.DemoActivity", "--es", "wake", e], {
          stdio: "ignore",
          env: { ...process.env, MSYS_NO_PATHCONV: "1" },
        });
        log(`push: forwarded (${e.length} chars)`);
      } catch {
        log("push: adb failed");
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ name: "projects/emu-test/messages/1" }));
      return;
    }
    res.writeHead(404).end();
  });
});
fake.listen(FCM_PORT, "127.0.0.1");

try {
  execFileSync(adb, ["reverse", `tcp:${SERVER_PORT}`, `tcp:${SERVER_PORT}`], { stdio: "ignore" });
} catch {
  log("adb reverse failed (emulator not running?)");
}

const wranglerLog = fs.openSync(path.join(work, "wrangler.log"), "a");
const wrangler = spawn(
  "npx",
  ["wrangler", "dev", "--local", "--port", String(SERVER_PORT), "--env-file", envFile, "--persist-to", path.join(work, "wrangler-state")],
  { cwd: path.join(root, "server"), shell: true, stdio: ["ignore", wranglerLog, wranglerLog] },
);
wrangler.on("exit", (c) => {
  log(`wrangler exit ${c}`);
  process.exit(1);
});
const stop = () => {
  // `shell: true` runs npx under cmd.exe: end the whole tree, not just the shell.
  try {
    execFileSync("taskkill", ["/pid", String(wrangler.pid), "/T", "/F"], { stdio: "ignore" });
  } catch {}
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
console.log(`fake FCM on 127.0.0.1:${FCM_PORT}, server on 127.0.0.1:${SERVER_PORT}`);
console.log(
  "phone: adb shell am start -n io.github.guidin9.warpshot/.DemoActivity --es push_token emu-fake-token",
);
