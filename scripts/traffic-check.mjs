// Traffic check (security plan item 8): nothing the server or FCM can read may
// carry content, item names or peer addresses (threat model, CLAUDE.md
// invariants). White-box and local: a `wrangler dev` server behind a recording
// TCP proxy, a fake FCM host that records every request, the agent as a test
// instance and the simulated phone. Both directions are exercised with marker
// strings in texts, file names and file contents; afterwards every recorded
// byte (proxy both ways, FCM bodies, the server's stored state, the server and
// agent logs) is searched for the markers and for this PC's network addresses.
// Plain http/ws on loopback, so the recording is what TLS would carry.
//
//   cargo build -p warpshot-agent; cargo build -p warpshot-ffi --example phone_sim
//   node scripts/traffic-check.mjs            (starts and stops its own server)
import { execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
const exe = (p) => path.join(root, "target", "debug", p);
const SERVER_PORT = 8797;
const FCM_PORT = 8798;
const PROXY_PORT = 8799;
const server = `http://127.0.0.1:${PROXY_PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "warpshot-traffic-"));
const dirs = Object.fromEntries(["agent", "phone", "received", "inbox", "files", "state"].map((d) => [d, path.join(tmp, d)]));
for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true });
fs.writeFileSync(path.join(dirs.agent, "config.json"), JSON.stringify({ server_url: server }));
fs.writeFileSync(
  path.join(dirs.agent, "settings.json"),
  JSON.stringify({ save_dir: dirs.received, on_receive: { clipboard: false, notify: false } }),
);

let failed = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${extra ? " — " + extra : ""}`);
  if (!ok) failed++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One random marker; every text, name and content below contains it.
const mk = "WSMK" + crypto.randomBytes(8).toString("hex");

// --- Recording proxy in front of the server -------------------------------
const recorded = { up: [], down: [] };
const proxy = net.createServer((c) => {
  const u = net.connect(SERVER_PORT, "127.0.0.1");
  c.on("data", (d) => recorded.up.push(Buffer.from(d)));
  u.on("data", (d) => recorded.down.push(Buffer.from(d)));
  c.pipe(u);
  u.pipe(c);
  c.on("error", () => u.destroy());
  u.on("error", () => c.destroy());
});
await new Promise((r) => proxy.listen(PROXY_PORT, "127.0.0.1", r));

// --- Fake FCM: records every request ---------------------------------------
const fcm = { bodies: [], pushes: [] };
const pushWaiters = [];
const fake = http.createServer((req, res) => {
  const parts = [];
  req.on("data", (d) => parts.push(d));
  req.on("end", () => {
    const body = Buffer.concat(parts);
    fcm.bodies.push(Buffer.concat([Buffer.from(`${req.method} ${req.url}\n${JSON.stringify(req.headers)}\n`), body]));
    if (req.method === "POST" && req.url === "/token") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "fake", expires_in: 3600 }));
      return;
    }
    if (req.method === "POST" && /^\/v1\/projects\/[^/]+\/messages:send$/.test(req.url ?? "")) {
      let m;
      try {
        m = JSON.parse(body.toString("utf8")).message;
      } catch {}
      fcm.pushes.push(m);
      for (const w of pushWaiters.splice(0)) w(m);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ name: "projects/traffic-test/messages/1" }));
      return;
    }
    res.writeHead(404).end();
  });
});
await new Promise((r) => fake.listen(FCM_PORT, "127.0.0.1", r));
const nextPush = (ms = 30000) =>
  new Promise((resolve, reject) => {
    pushWaiters.push(resolve);
    setTimeout(() => reject(new Error("timeout waiting for a push")), ms);
  });

// --- Server ----------------------------------------------------------------
const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const sa = {
  type: "service_account",
  project_id: "traffic-test",
  client_email: "fake@traffic-test.iam.gserviceaccount.com",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
};
const envFile = path.join(tmp, "fcm.env");
fs.writeFileSync(envFile, `FCM_SERVICE_ACCOUNT='${JSON.stringify(sa)}'\nFCM_BASE_URL=http://127.0.0.1:${FCM_PORT}\n`);
const wranglerLogPath = path.join(tmp, "wrangler.log");
const wranglerLog = fs.openSync(wranglerLogPath, "a");
const wrangler = spawn(
  "npx",
  ["wrangler", "dev", "--local", "--port", String(SERVER_PORT), "--inspector-port", "9239", "--env-file", envFile, "--persist-to", dirs.state],
  { cwd: path.join(root, "server"), shell: true, stdio: ["ignore", wranglerLog, wranglerLog] },
);
const stopWrangler = () => {
  // `shell: true` runs npx under cmd.exe: end the whole tree, workerd included.
  try {
    execFileSync("taskkill", ["/pid", String(wrangler.pid), "/T", "/F"], { stdio: "ignore" });
  } catch {}
};
let up = false;
for (let i = 0; i < 120 && !up; i++) {
  await sleep(500);
  up = await new Promise((r) => {
    const q = http.get(`http://127.0.0.1:${SERVER_PORT}/v1/health`, (res) => {
      res.resume();
      r(res.statusCode === 200);
    });
    q.on("error", () => r(false));
  });
}
if (!up) {
  console.log("FAIL server did not start; see " + wranglerLogPath);
  stopWrangler();
  process.exit(1);
}
recorded.up.length = recorded.down.length = 0; // health probes went direct anyway

// --- Agent (test instance) and phone ----------------------------------------
const sid = execFileSync(path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "whoami.exe"), ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" }).trim().split(",")[1].replace(/"/g, "");
const instance = `traffic${process.pid}`;
const pipeName = `\\\\.\\pipe\\warpshot-${sid}-${instance}`;
const agentOut = path.join(tmp, "agent-output.log");
const agentOutFd = fs.openSync(agentOut, "a");
const agent = spawn(exe("warpshot-agent.exe"), [], {
  env: { ...process.env, WARPSHOT_DATA_DIR: dirs.agent, WARPSHOT_INSTANCE: instance },
  stdio: ["ignore", agentOutFd, agentOutFd],
});

function phone(...args) {
  return new Promise((resolve) => {
    const p = spawn(exe("examples/phone_sim.exe"), [dirs.phone, server, ...args]);
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("exit", (code) => resolve({ ok: code === 0, out: out.trim() }));
  });
}

async function connect() {
  for (let i = 0; i < 100; i++) {
    try {
      return await new Promise((res, rej) => {
        const s = net.connect(pipeName, () => res(s));
        s.once("error", rej);
      });
    } catch {
      await sleep(100);
    }
  }
  throw new Error("agent pipe not available");
}

let sock;
try {
  sock = await connect();
  let nextId = 1;
  const pending = new Map();
  const waiters = [];
  let buf = "";
  sock.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const m = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      if (m.id !== undefined && pending.has(m.id)) {
        pending.get(m.id)(m);
        pending.delete(m.id);
      } else if (m.event) {
        for (const w of [...waiters]) if (w.name === m.event) { w.resolve(m.data); waiters.splice(waiters.indexOf(w), 1); }
      }
    }
  });
  const rpc = (method, params) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, (m) => (m.error ? reject(m.error) : resolve(m.result)));
      sock.write(JSON.stringify({ id, method, params }) + "\n");
    });
  const waitEvent = (name, ms = 60000) =>
    new Promise((resolve, reject) => {
      waiters.push({ name, resolve });
      setTimeout(() => reject(new Error(`timeout waiting for ${name}`)), ms);
    });

  // Pairing.
  const { qr_text } = await rpc("pair.start");
  const sas = waitEvent("pair.sas");
  const done = waitEvent("pair.done");
  const ph = phone("pair", qr_text);
  await sas;
  await rpc("pair.confirm", { accept: true });
  await done;
  check("pairing", (await ph).ok);
  const me = (await rpc("devices.list")).find((x) => x.me).id;
  let r = await phone("push-token", "traffic-test-token");
  check("phone push token", r.ok, r.out);
  await sleep(1500); // the agent's WebSocket connects after pairing

  // Phone → PC: a text and a file whose name and content carry the marker.
  r = await phone("send-text", me, `phone text ${mk}-pt`);
  check("phone → PC text", r.ok, r.out.split("\n").at(-1));
  const pf = path.join(dirs.files, `${mk}-phone-name.txt`);
  fs.writeFileSync(pf, `${mk}-phone-content\n`.repeat(4096));
  r = await phone("send-file", me, pf);
  check("phone → PC file", r.ok && fs.existsSync(path.join(dirs.received, path.basename(pf))), r.out.split("\n").at(-1));

  // PC → phone through FCM: the push's envelope goes to the simulated phone.
  async function pcToPhone(name, method, params) {
    const push = nextPush();
    const tdone = waitEvent("transfer.done");
    await rpc(method, params);
    const m = await push;
    const w = await phone("wake", m?.data?.e ?? "", dirs.inbox);
    const t = await tdone;
    check(name, w.ok && w.out.endsWith("received 1") && t.ok === true, `${w.out.split("\n").at(-1)}; ${JSON.stringify(t)}`);
    return m;
  }
  const m1 = await pcToPhone("PC → phone text", "send.text", { text: `pc text ${mk}-ct` });
  const cf = path.join(dirs.files, `${mk}-pc-name.bin`);
  fs.writeFileSync(cf, `${mk}-pc-content\n`.repeat(4096));
  await pcToPhone("PC → phone file", "send.files", { paths: [cf] });
  check("phone inbox has the file", fs.readdirSync(dirs.inbox).length >= 1, String(fs.readdirSync(dirs.inbox).length));

  // The push carries only the opaque envelope (protocol §6.5: no notification
  // block, no plaintext sender or kind).
  const keys = (o) => Object.keys(o ?? {}).sort().join();
  check(
    "FCM message shape",
    fcm.pushes.length >= 2 &&
      fcm.pushes.every((p) => keys(p) === "android,data,token" && keys(p.android) === "priority,ttl" && keys(p.data) === "e,v" && p.data.v === "1"),
    `${keys(m1)}; data ${keys(m1?.data)}`,
  );
} catch (e) {
  check("run", false, String(e?.message ?? JSON.stringify(e)));
} finally {
  sock?.destroy();
  agent.kill();
  await sleep(500);
  stopWrangler();
  proxy.close();
  fake.close();
  await sleep(1000);
}

// --- Search everything the server, FCM and the logs saw ---------------------
// A string is searched raw (UTF-8), as UTF-16LE, as hex and as base64/base64url
// at every alignment, so an encoded copy is found too.
function forms(bytes) {
  const out = [bytes, Buffer.from(bytes.toString("latin1"), "utf16le"), Buffer.from(bytes.toString("hex"))];
  for (let k = 0; k < 3; k++) {
    const b = Buffer.concat([Buffer.alloc(k), bytes]).toString("base64");
    const s = b.slice(k ? 4 : 0, Math.floor((k + bytes.length) / 3) * 4);
    out.push(Buffer.from(s), Buffer.from(s.replace(/\+/g, "-").replace(/\//g, "_")));
  }
  return out;
}
const addrs = Object.values(os.networkInterfaces())
  .flat()
  .filter((a) => a && !a.internal)
  .map((a) => a.address.split("%")[0]);
const needles = [{ what: "marker", forms: forms(Buffer.from(mk)) }];
for (const a of addrs) {
  const f = forms(Buffer.from(a));
  f.push(net.isIPv4(a) ? Buffer.from(a.split(".").map(Number)) : ipv6Bytes(a));
  needles.push({ what: `address ${net.isIPv4(a) ? "v4" : "v6"}`, forms: f });
}
function ipv6Bytes(a) {
  const [h, t = ""] = a.split("::");
  const hs = h ? h.split(":") : [];
  const ts = t ? t.split(":") : [];
  const groups = a.includes("::") ? [...hs, ...Array(8 - hs.length - ts.length).fill("0"), ...ts] : hs;
  return Buffer.from(groups.flatMap((g) => { const n = parseInt(g, 16); return [n >> 8, n & 255]; }));
}
function filesUnder(d) {
  return fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? filesUnder(path.join(d, e.name)) : [path.join(d, e.name)]));
}
const sources = {
  "client → server": Buffer.concat(recorded.up),
  "server → client": Buffer.concat(recorded.down),
  "FCM requests": Buffer.concat(fcm.bodies),
  "server state at rest": Buffer.concat(filesUnder(dirs.state).map((f) => fs.readFileSync(f))),
  "server log": fs.readFileSync(wranglerLogPath),
  "agent output": fs.readFileSync(agentOut),
};
const sizes = Object.entries(sources).map(([k, v]) => `${k} ${v.length} B`).join(", ");
check("traffic recorded", sources["client → server"].length > 10000 && sources["server → client"].length > 1000 && sources["FCM requests"].length > 0, sizes);
// Compression would hide plaintext from this search: make sure there is none.
const headers = (sources["client → server"].toString("latin1") + sources["server → client"].toString("latin1")).toLowerCase();
check("no compressed bodies or frames", !headers.includes("permessage-deflate") && !/content-encoding: *(gzip|br|deflate)/.test(headers));
// Sanity: the search does find the marker where it must be (the received files).
check("search finds the marker in a received file", forms(Buffer.from(mk)).some((f) => fs.readFileSync(path.join(dirs.received, `${mk}-phone-name.txt`)).includes(f)));
for (const [src, data] of Object.entries(sources)) {
  const hits = needles.filter((n) => n.forms.some((f) => data.includes(f))).map((n) => n.what);
  check(`no content, names or addresses in ${src}`, hits.length === 0, hits.join(", "));
}
console.log(`checked ${addrs.length} local addresses`);

if (failed) console.log(`work dir kept: ${tmp}`);
else try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
console.log(failed ? `${failed} FAILED` : "ALL PASSED");
process.exit(failed ? 1 : 0);
