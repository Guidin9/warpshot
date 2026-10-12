// Security plan item 9: mutation fuzzing of every server decoder. Pure
// decoders get many deterministic inputs and may only throw their own error
// classes; signed but malformed HTTP and WebSocket requests must never end in
// "internal" (an uncaught error), and the socket must stay usable.
// More inputs: FUZZ_N=50000 npm test -- fuzz (vitest.config.ts passes it on).
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { parseAuthorization } from "../src/auth";
import { b64uDecode, b64uEncode } from "../src/b64u";
import { CborError, CborShapeError, decodeCbor } from "../src/cbor";
import { emptyState, parseSignedRecord, RecordError, validateRecord } from "../src/record";
import { ApiError, parseJsonObject, utf8 } from "../src/util";
import {
  addBody,
  authHeader,
  call,
  connect,
  createGroup,
  device,
  Device,
  genesisBody,
  newGroupId,
  signRecord,
  TestGroup,
} from "./helpers/fixtures";

const N = Number(env.FUZZ_N) || 3000;

/** xorshift32, so a failure reproduces from the printed input. */
function rng(seed: number): (n: number) => number {
  let s = seed >>> 0 || 1;
  return (n) => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return n <= 0 ? 0 : s % n;
  };
}

// CBOR length boundaries, JSON delimiters, CR/LF.
const INTERESTING = [0x00, 0x01, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x7f, 0x80, 0xff, 0x22, 0x5c, 0x7b, 0x5b, 0x0d, 0x0a];

/** Random bytes (a quarter of the time) or a seed with 1–4 mutations; same operators as the Rust side. */
function mutate(r: (n: number) => number, seeds: Uint8Array[]): Uint8Array {
  if (r(4) === 0) return Uint8Array.from({ length: r(64) }, () => r(256));
  const b = [...seeds[r(seeds.length)]!];
  for (let k = r(4); k >= 0; k--) {
    const len = b.length;
    switch (r(8)) {
      case 0:
        if (len) b[r(len)] = r(256);
        break;
      case 1:
        if (len) b[r(len)]! ^= 1 << r(8);
        break;
      case 2:
        if (len) b[r(len)] = INTERESTING[r(INTERESTING.length)]!;
        break;
      case 3:
        if (len) b.splice(r(len), 1);
        break;
      case 4:
        b.splice(r(len + 1), 0, r(256));
        break;
      case 5:
        if (len) {
          const i = r(len);
          b.splice(r(len + 1), 0, ...b.slice(i, i + 1 + r(16)));
        }
        break;
      case 6:
        if (len) {
          const o = seeds[r(seeds.length)]!;
          b.length = r(len);
          b.push(...o.slice(r(o.length + 1)));
        }
        break;
      default:
        b.length = r(len + 1);
    }
  }
  return Uint8Array.from(b);
}

const hexOf = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const text = (b: Uint8Array) => new TextDecoder().decode(b); // lossy, like the Rust side

type ErrorClass = abstract new (...args: never[]) => Error;

/** Runs `f` on `n` inputs; only `allowed` errors may escape. Returns the accepted count. */
async function fuzz(
  seeds: Uint8Array[],
  n: number,
  allowed: ErrorClass[],
  f: (b: Uint8Array) => boolean | Promise<boolean>,
): Promise<number> {
  const r = rng(0x5eed);
  let accepted = 0;
  for (let i = 0; i < n; i++) {
    const b = mutate(r, seeds);
    try {
      if (await f(b)) accepted++;
    } catch (e) {
      if (!allowed.some((c) => e instanceof c)) throw new Error(`input ${hexOf(b)}: ${String(e)}`);
    }
  }
  return accepted;
}

describe("pure decoders", () => {
  it("decodeCbor: only CborError", async () => {
    const seeds = ["a4010203424142056161074101", "83010203", "a201820102038144deadbeef", "1bffffffffffffffff", "f5"].map(
      (h) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16))),
    );
    const ok = await fuzz(seeds, N * 10, [CborError], (b) => (decodeCbor(b, { maxBytes: 4096 }), true));
    expect(ok).toBeGreaterThan(0);
  });

  it("b64uDecode: never throws; accepted text is canonical", async () => {
    const seeds = ["", "AA", "AAE", "AAEC", "-_8", "hAFIAeun9j6-O95ZBGCGuIcstqqHcLjWzpe9kOfM"].map(utf8);
    const ok = await fuzz(seeds, N * 10, [], (b) => {
      const s = text(b);
      const v = b64uDecode(s);
      if (v === null) return false;
      expect(b64uEncode(v)).toBe(s);
      return true;
    });
    expect(ok).toBeGreaterThan(0);
  });

  it("parseAuthorization: only ApiError", async () => {
    const A = await device(1);
    const seeds = [utf8(await authHeader(A, "POST", "/v1/groups/x/log", utf8("{}"), 1_790_000_000_000))];
    const ok = await fuzz(seeds, N * 10, [ApiError], (b) => (parseAuthorization(text(b)), true));
    expect(ok).toBeGreaterThan(0);
  });

  it("parseJsonObject: only ApiError", async () => {
    const seeds = [`{"record":"AAEC"}`, `{"to":"AA","env":"QUJD","ttl":60}`, `{"provider":"fcm","token":"t"}`].map(utf8);
    const ok = await fuzz(seeds, N * 10, [ApiError], (b) => (parseJsonObject(b), true));
    expect(ok).toBeGreaterThan(0);
  });

  it("parseSignedRecord and validateRecord: only their own errors, state untouched", async () => {
    const A = await device(1);
    const B = await device(2);
    const gid = newGroupId();
    const now = Date.now();
    const g = await signRecord(genesisBody(gid, A, now), A);
    const parsedG = parseSignedRecord(g.bytes);
    const after = await validateRecord(emptyState(gid), parsedG, now);
    const add = await signRecord(addBody(gid, 1, after.id, B), A);
    const state = after.state;
    const snap = () => JSON.stringify([state.seq, b64uEncode(state.headId ?? new Uint8Array()), [...state.members.keys()]]);
    const before = snap();
    // Accepted = parsed; a mutated record practically never passes validation (signature).
    const ok = await fuzz([g.bytes, add.bytes], N, [CborError, CborShapeError, RecordError], async (b) => {
      const p = parseSignedRecord(b);
      try {
        await validateRecord(state, p, now);
      } catch (e) {
        if (!(e instanceof RecordError || e instanceof CborShapeError)) throw e;
      }
      return true;
    });
    // validateRecord returns a new state; the input state must never change.
    expect(snap()).toBe(before);
    expect(ok).toBeGreaterThan(0);
  });
});

describe("signed but malformed requests", () => {
  /** A fresh group every few requests, so rate limits don't hide the parsers. */
  async function group(A: Device, B: Device): Promise<TestGroup> {
    return createGroup(A, [B]);
  }

  async function noInternal(res: Response, b: Uint8Array): Promise<void> {
    const t = await res.text();
    if (res.status >= 500 || t.includes('"internal"')) throw new Error(`${res.status} ${t} for ${hexOf(b)}`);
  }

  it("HTTP bodies on every route: never internal", async () => {
    const A = await device(1);
    const B = await device(2);
    let tg = await group(A, B);
    const rec = await signRecord(addBody(tg.groupId, 2, tg.head, await device(3)), A);
    const routes: Array<{ method: string; path: (t: TestGroup) => string; seeds: string[] }> = [
      { method: "POST", path: (t) => t.path("log"), seeds: [`{"record":"${rec.b64}"}`] },
      { method: "POST", path: (t) => t.path("wake"), seeds: [`{"to":"${B.id}","env":"QUJD${"y".repeat(200)}","ttl":60}`] },
      { method: "PUT", path: (t) => t.path("push-token"), seeds: [`{"provider":"fcm","token":"tok:abc-_1"}`] },
      { method: "POST", path: () => "/v1/groups", seeds: [`{"genesis":"${rec.b64}"}`] },
    ];
    const r = rng(0x5eed);
    const n = Math.max(40, Math.floor(N / 30));
    for (const route of routes) {
      const seeds = route.seeds.map(utf8);
      for (let i = 0; i < n; i++) {
        if (i % 8 === 7) tg = await group(A, B);
        const b = mutate(r, seeds);
        await noInternal(await call(A, route.method, route.path(tg), undefined, { rawBody: b }), b);
      }
    }
  }, 180_000);

  it("WebSocket messages: never internal, socket stays usable", async () => {
    const A = await device(1);
    const B = await device(2);
    const tg = await group(A, B);
    const s = await connect(tg, A);
    const seeds = [
      `{"t":"wake","id":1,"to":"${B.id}","env":"QUJD${"y".repeat(200)}","ttl":60}`,
      `{"t":"presence","id":2}`,
      `{"t":"log-get","id":3,"after":0}`,
    ].map(utf8);
    const r = rng(0x5eed);
    const n = Math.max(100, Math.floor(N / 10));
    for (let i = 0; i < n; i++) s.ws.send(text(mutate(r, seeds)));
    s.ws.send(`{"t":"presence","id":999999}`);
    // Every reply is read; the last one answers the final, valid request.
    let reply = "";
    for (;;) {
      reply = await s.next(5000);
      expect(reply).not.toContain('"internal"');
      if (reply.includes('"id":999999')) break;
    }
    // Rate limiting may answer the final request, but the socket is still open and answering.
    expect(reply).toMatch(/"t":"(presence|err)"/);
  }, 180_000);
});
