# Roadmap and task list

Each task is sized for one agent session, so it can be verified independently.
**Acceptance** says how to verify it. `[DL]` marks tasks that need large
downloads (toolchains, SDKs, first dependency fetch); schedule those for a fast
connection (`docs/dev-setup.md`).

## Faz 0 — Foundations and spikes

- [x] **F0-1** Repo skeleton, license, `CLAUDE.md`, the docs (architecture,
  protocol, threat model, resource budget, spikes, ADRs, dev setup).
- [x] **F0-2** `scripts/setup-dev.ps1` (dry run tested) and `scripts/measure-idle.ps1`
  (tested on Windows PowerShell 5.1: over-budget and within-budget cases).
- [x] **F0-3** `[DL]` Run `setup-dev.ps1` on a fast connection.
  Acceptance: the verification block shows MSVC installed and rustc with host
  `x86_64-pc-windows-msvc`; `cargo new` + `cargo run` works.
- [x] **F0-4** Accounts (user): Cloudflare (`npx wrangler login`); a Firebase
  project with the Android app and a service-account key.
- [x] **F0-5** Decide names: app name **Warpshot** (formerly the working name
  `pictransfer`), Android `applicationId` `io.github.guidin9.warpshot`, Worker
  name `warpshot`. Binaries: `warpshot-agent.exe`, `warpshot-ui.exe`, `warpctl`.
- [x] **F0-6** `[DL]` Spike A — iroh on demand (`docs/spikes.md`). Windows part done
  2026-10-09; the phone side was measured with the product app instead
  (spikes.md "Phone ↔ PC routes").
- [x] **F0-7** `[DL]` Spike B — agent skeleton vs the idle budget; first row in
  `resource-budget.md` §4.
- [x] **F0-8** `[DL]` Spike C — DO keepalive. Set K in protocol §6.3.
- [x] **F0-9** `[DL]` Spike D — Android wake path on the user's phone. Measured
  with the product app (spikes.md Spike D); the Doze row is still open.
- [x] **F0-10** ADR 0008, crate choices: X-Wing implementation, CBOR crate
  (`minicbor` vs `ciborium`, judged by strict-decoding support), SQLite binding.

## Faz 1 — MVP (personal use)

### Core (`crates/core`)

| Id | Task | Acceptance |
|---|---|---|
| C1 ✓ | Strict CBOR helpers (limits, rejection rules) + fuzz target | `cbor-reject.json` passes; 10 min of fuzzing clean |
| C2 | Keys and keystore trait (DPAPI impl in the agent; Android via an FFI callback) | round-trip tests; keys never appear in `Debug` output |
| C3 ✓ | Membership log: records, §4.3 validation, state, append/CAS logic, fork detection | `record.json` vectors; property tests (random ops, forks, re-adds) |
| C4 ✓ | Wake envelopes §7: seal/open, replay cache | `wake.json` vectors; every tamper case rejected |
| C5 ✓ | Server client: §6.1 auth, REST, WebSocket (keepalive, backoff, resume) | `server-auth.json`; integration test against `wrangler dev` |
| C6 ✓ | Endpoint manager: on-demand bind, 30 s idle teardown, single relay, no address lookup, direct-only policy | unit tests + spike A numbers reproduced |
| C7 ✓ | Transfer §8: handshake and key schedule, control messages, item streams, BLAKE3, temp file + atomic rename, name sanitization | `xfer-keys.json`; warpctl E2E with text, image and a 1 GB file; relay-only and direct-only modes |
| C8 ✓ | Pairing §5: QR encode/decode, SAS, group resolution table | `pair.json`; warpctl pairing E2E covering all 5 table rows |
| C9 ✓ | Settings store and history store (encrypted fields) | tests; no plaintext names in the DB file |
| C10 ✓ | Test-vector generator (`gen_vectors`) used by core and server | vectors reproducible from fixed seeds |

### CLI (`crates/cli`, `warpctl`)

| Id | Task | Acceptance |
|---|---|---|
| L1 ✓ | `init`, `pair-display`, `pair-scan <qr>`, `send <device> <path>` / `send <device> --text`, `listen`, `devices`, `log`, `remove` | `scripts/e2e-local.ps1` green |

### Server (`server/`)

| Id | Task | Acceptance |
|---|---|---|
| S1 ✓ | Worker router + DO skeleton (SQLite schema, Hibernation API, auto-response) | vitest (workers pool) |
| S2 ✓ | §6.1 auth + replay cache (WebCrypto Ed25519) + operator admission token | `server-auth.json` vectors; group creation without/with a wrong token → 403 `not-allowed` |
| S3 ✓ | Log store: §4.3 validation + CAS + `log` push | `record.json` vectors shared with core |
| S4 ✓ | Wake routing (WS, else FCM HTTP v1 with cached OAuth token), rate limits | tests with a fake FCM endpoint |
| S5 ✓ | Presence, push-token endpoints, removal handling (`bye`, token deletion) | tests |
| S6 ✓ | Deploy (wrangler), secrets, `/v1/health` | health check on the free account |

### Windows agent (`apps/windows-agent`)

| Id | Task | Acceptance |
|---|---|---|
| W1 ✓ | Message loop, tray (devices + status, default-target radio, settings, quit), single instance | manual check; idle budget |
| W2 | Global hotkey + AltGr conflict check; toast if the hotkey is taken | TR-Q: `Ctrl+Alt+Q` flagged |
| W3 ✓ | Clipboard read (PNG, DIBV5, text, CF_HDROP) and write (PNG + DIBV5, text, CF_HDROP) | paste works in Paint, Word, Explorer |
| W4 | WinRT toasts with preview + COM activator; Start Menu shortcut with AUMID | the action opens the right history item; no URL handler is registered |
| W5 ✓ | Receive pipeline: save with MOTW, clipboard, toast, history | `Zone.Identifier` present; sanitization tests |
| W6 ✓ | Named-pipe JSON-RPC server (user-SID ACL, remote clients rejected) | another local user is refused |
| W7 | Resource discipline: on-demand endpoint, working-set trim, EcoQoS | `measure-idle.ps1` within budget |
| W8 | Autostart (HKCU Run) + per-user installer | clean install/uninstall, no admin rights |

### Windows UI (`apps/windows-ui`)

| Id | Task | Acceptance |
|---|---|---|
| U1 | Tauri v2 skeleton: no network capability, strict CSP, pipe client | `warpshot-ui` exits fully on close (no leftover WebView2 processes) |
| U2 | Screens: pairing (QR, SAS, confirm), devices (rename/remove), settings (hotkey recorder with AltGr warning, target, folder, relay, autostart), history | manual walkthrough |

### Android (`apps/android`)

| Id | Task | Acceptance |
|---|---|---|
| A1 ✓ | Gradle project; Rust core via `cargo-ndk` + UniFFI; Keystore bridge | debug build on the phone |
| A2 ✓ | Onboarding: QR scan, pairing confirmation, notification permission, battery guidance | pairs with warpctl and with the agent |
| A3 | FCM → `TransferService` (dataSync FGS) → receive → outputs (MediaStore, clipboard, notification, history) | delivery in Doze, < 3 s on Wi-Fi |
| A4 ✓ | `ShareActivity` + sharing shortcuts (the PC appears directly in the share sheet) | share an image from Gallery → PC clipboard |
| A5 ✓ | Devices (presence), settings, history; group alerts with "This wasn't me" | the alert appears when warpctl adds a device |

### End-to-end and personal release

| Id | Task | Acceptance |
|---|---|---|
| E1 | `scripts/e2e-local.ps1`: `wrangler dev` + two `warpctl` peers | green locally and in CI |
| E2 | Real-device checklists: `resource-budget.md`, `threat-model.md` §6, Spike D numbers | all checked |
| E3 | CI (GitHub Actions): fmt, clippy, test, deny; server tests; Windows agent build + idle gate; Android assemble | green on `main` |

## Pairing recovery and presence (2026-10-15)

- [x] Reproduce PC removal followed by phone removal failure and repeated QR
  pairing failure. Readmit the stale phone only after fresh mutual confirmation;
  retain verified history and reject rollback/forks. Recovery vectors cover
  user and not-me removal (lost/stolen: see 2026-10-16); refusal on either side
  keeps it removed.
- [x] Android shows actionable group-access recovery instead of retaining a
  usable-looking PC card after `not-member`. Keys/logs are preserved. Windows
  distinguishes online, notification-reachable and unreachable devices, and
  refreshes presence on UI demand without another idle timer.
- [x] Local Worker + isolated release agent + phone_sim: remove, rejected
  phone operation, retained trust history, re-pair, sync, send, old push-token
  deletion and new registration all pass. Core attack suite: 12 pass.
- [ ] Real-phone confirmation: install the prepared APK/PC builds, recover the
  user's existing pairing, verify both directions and investigate the original
  failed wake. No real device state was reset during the isolated tests.
  2026-10-15: installed on both; the user re-paired and a transfer worked
  (direction and background wake not checked).

## Lost-or-stolen revocation, presence fallback, send progress (2026-10-16)

- [x] Revoked set `R` (protocol §4.3): a key removed as lost or stolen is never
  added again; core, server and `record.json` vectors (`AddRevoked`). The PC
  refuses such a scanner before the SAS (`PAIR_REVOKED`, §5.3); Android offers
  "Reset this phone" (clear app data → new identity, new push token).
  `pair-recovery.json` + e2e: refused, then a new identity pairs.
- [x] `devices.list` refreshes presence only while the server is connected,
  waits at most 3 s and falls back to the last known presence (the Devices and
  Settings pages no longer fail offline). Agent `pair.failed` now reports
  `other-group` and `revoked` instead of `network`.
- [x] Hotkey send flyout: "Waking …" → "Connected to …" → progress bar with
  percent, sizes and speed; after 5 s without bytes the bar turns amber and says
  "no data for N s". Its 1 s timer exists only while the bar is shown.
- [ ] Deploy the server (the `R` rule) — honest clients already refuse; the
  server rule stops a malicious member's re-add.
- [ ] Real phone: "Reset this phone" end to end in the emulator test group only
  (needs a lost-or-stolen removal; never the real group).

## Faz 2 and 3

See [`architecture.md`](architecture.md) §11 for the planned extensions.
Faz 3 (public release) adds code signing (SignPath Foundation), the Play Store,
a self-host option, TPM keys, UnifiedPush/F-Droid, reproducible builds and an
external audit.

## Project end: full documentation (user request, 2026-10-10)

Before the project is called done, write detailed documentation on every
aspect of the app, for the user as well as for contributors: what it does and
how to use it on both platforms (pairing, sending, history, settings, removing
a lost device); how it works (direct path vs. relay, what our server does and
does not see, wake-ups, the device group and its log, the encryption layers);
installation, update and uninstall; troubleshooting (slow transfers, firewall,
Doze, notifications); privacy and security in plain language; self-deployment
of the server; building from source; and a glossary of terms (relay, direct
path, NAT, port mapping, endpoint, membership log).

## Next session (from the user's testing, 2026-10-10)

1. ✓ **Mobile UI redesign** (Compose, Material 3 with the wallpaper's colors;
   a blue fallback before Android 12): onboarding with three steps that use
   the PC UI's own labels and a large SAS dialog; the paired screen with the
   target PC, Photos (system photo picker, no media permission), Files,
   a text field with Paste, running transfers with Cancel, a notifications
   card and tips; the share sheet as a bottom sheet with a preview (thumbnail
   or name and size, or the text) and a PC choice when several are paired
   (remembered). Pairing state lives outside the screen and the activities
   handle rotation in place, so neither a pairing nor a copy in progress is
   lost. Adaptive launcher icon and status-bar icon match the PC icon
   (themed icons supported). Found while testing and fixed: a send could
   wait forever if the iroh bind never returned, and Cancel didn't work
   before the PC dialed in (FFI: 20 s bind limit, Cancel during bind and
   wake; e2e check "phone cancel while waking": 0.4 s, 10.9 s before);
   copies left by a killed process stayed in the cache (swept on the next
   start); photo-picker items arrived as "20.png" (now `IMG_<date>`).
   Checked in the emulator (docs/dev-setup.md §9) in both languages and
   themes, and live against a test group: pairing with matching SAS,
   notification permission denied → card → granted, text, photo picker and
   a 40 MB file to the PC, share sheet. Live check (S21 FE, 2026-10-10,
   installed over the old build, pairing kept): text from the home screen
   (snackbar), PC → phone 30 MB with its progress on the home screen
   (10.9 s, direct), phone → PC 30 MB via Files (4.5 s, ~8 MB/s, direct),
   the photo picker (arrived as `IMG_20261010_184819.png`), the share sheet
   (text sent and the sheet closed within 2 s).
   Fixed later: received partial files left in `cache/inbox` by a killed
   process are swept on the next start (checked on the phone with a planted
   `.part` file). Release builds use R8 (rules in `proguard-rules.pro`, incl.
   Firebase/ML Kit registrar constructors): APK 33.3 → 11.6 MB, background
   memory 103 → 50 MB PSS; FCM wake of a killed app checked (187 ms).
1b. ✓ **Android completeness (2026-10-10, user's pick):** history (home
   "Recent" + full list; copy again, open, delete, clear), a Devices screen
   (PC online state, rename this phone, remove a device), sharing shortcuts
   per PC, a "Send to PC" Quick Settings tile (sends the clipboard) and a
   Settings screen (clipboard on receive, history on/off, notifications,
   battery optimization, tile, about). Received items now name their real
   sender (FFI `ReceivedItem.peer`), which also fixes the sender's name with
   several PCs. Live check on the S21 FE: history filled from both
   directions, presence "Online", all four screens, clear history; the
   shortcut is registered (`dumpsys shortcut`). Not checked live: removing
   a device and renaming (would change the real group; same signed-append
   path as the agent's), the tile (needs adding to the panel by hand), the
   share-sheet shortcut row.
2. ✓ **Hotkey feedback on the PC:** an on-screen flyout above the taskbar
   (`osd.rs`) says "Sending to …" the moment the hotkey is pressed, then
   "Sent to …" or "Not sent: …"; it never takes focus, lets clicks through
   and is destroyed when it hides. Toast banners were the wrong channel:
   Windows hides them during full-screen apps, games and streams (the "Sent"
   toasts were in the notification center). Failures still also toast. The
   agent is now per-monitor DPI aware. Dev check: `--render-flyout DIR`.
3. ✓ **Progress bar for sends** (both directions, both platforms): the core
   reports item-data progress and a smoothed rate at most 4×/s
   (`Session::on_progress`) → FFI `TransferObserver.on_progress` → the share
   card and the ongoing notification on Android; `transfer.started /
   progress / done` on the PC (docs/ipc.md) → "Süren aktarımlar" in the UI
   (bar, %, MB/s, time left) and the tray tooltip.
4. ✓ **Tray icon has no logo** (shows blank in hidden icons): load a real
   icon resource in `tray.rs`, embed it in the exe.
4b. ✓ **Active transfers view + cancel (both platforms):** cancel = close with
   the new `CANCELLED` code (protocol §8.4, §8.8); the receiver deletes
   partial files (also fixed: a `.part` file stayed behind when the
   connection died between the last chunk and `ItemDone`); "cancelled" is
   never reported as a failure. Android: sends run in `TransferService`
   (foreground) — the share card shows progress with Cancel / "Continue in
   background", the ongoing notification has Cancel ("Cancel all" for
   several). PC: Cancel buttons in the UI, a Cancel item per transfer in the
   tray menu, `transfer.list` / `transfer.cancel`. Tests: core e2e
   (receiver/sender/early cancel, no files left), agent e2e (PC-side and
   phone-side cancel, progress events; runs beside the real agent via the
   debug-only `WARPSHOT_INSTANCE`). Known limit: a send cancelled while
   waiting for the woken phone may still make the phone show "Couldn't
   receive" when it answers late (same as an expired wait). Live check
   (S21 FE + PC, 2026-10-10): PC → phone 30 MB complete with progress, 20 MB
   cancelled from the PC (nothing saved, no error notice, service stopped),
   the phone's notification showed progress with Cancel; phone → PC share
   with the card and notification checked by the user. Agent idle after the
   change: 0.83 MB private working set, 0 % CPU, 5 threads.
4c. ✓ **LAN speed (2026-10-10):** measured (spikes.md "Phone ↔ PC routes"):
   on the same AP the direct path works at Wi-Fi speed (100 MB in 13 s, no
   firewall rule needed); the 27 min came from a repeater AP that breaks ARP
   between the phone and the wired PC, so everything went through the
   rate-limited n0 relay. Done in the app: a "Slow connection" notice after
   8 s on the relay (PC toast + `transfer.slow` event; Android notification
   via the FFI `TransferObserver`) and route counters (`debug.counters`
   `route_*`, Android logcat line). Live check: PC → phone 20 MB with the
   phone on the repeater took 73 s on the relay; both notices appeared and
   `route_slow` counted it. Tray icon embedded (item 4).
   **Update (2026-10-10, later):** the real cause of slow phone → PC was
   UDP segmentation offload on the phone (spikes.md); GSO is now off on
   Android and phone → PC goes direct at Wi-Fi speed on "Public" networks too.
   **Open decision (user, later):** our own relay for fast non-direct
   transfers (a small VPS or a free cloud VM; not $0-by-default).
5. ✓ **Windows UI history bug:** long names were cut off hard at the
   "Klasörde göster" button. Now names end in "…" (full name in the tooltip),
   the "failed" badge never shrinks, size/date don't break mid-value, and
   below 860 px the reveal button is icon-only (checked headless at 720 and
   960 px with long Turkish names).
6. **Security tests for key theft:** stolen-key scenario, revocation
   ("lost or stolen") refusal, whether past transfers stay safe (forward
   secrecy) — add to the security plan below.
7. Open: Doze/locked-phone delivery test; iroh transient threads after transfers.
   Done (2026-10-12): server redeployed with the BOM-tolerant FCM parse; the
   orphaned first Firebase key deleted (the never-used one, by the per-key
   authentication metrics; the key in use stays).

8. ✓ **Language (2026-10-10):** the agent (toasts, tray, flyout), the
   settings window and the Android app follow the system language: Turkish
   on a Turkish system, English otherwise (`WARPSHOT_LANG=en|tr` overrides
   the agent; Android uses `values-tr`). Checked live (phone notifications
   in Turkish) and headless in both languages.
9. ✓ **Small fixes (2026-10-10):** a receive that is cancelled or fails after
   some items were saved now still reports those items (history,
   notifications, gallery; `Session::receive_keep`); "sent" notices on
   Android have their own notification channel.
10. ✓ **Cancel while waking (2026-10-12):** a send cancelled while waiting
    for the woken device no longer makes that device show "Couldn't receive"
    when it dials in late. One accept loop per endpoint (`net::dispatch`)
    hands each connection to the send waiting for its session, closes a late
    dial for a cancelled session with `CANCELLED` until the session would have
    expired (the endpoint stays open that long), and gives pairing
    connections to the pairing window; the separate per-send and pairing
    accept loops, which could close each other's connections, are gone, and
    on Android a failed admission of some other connection no longer aborts
    the send. Protocol §9 "Pending sessions". Tests: core e2e (delivered,
    cancelled before and after the dial arrived, unknown / withdrawn /
    expired sessions refused, pairing routed while a send waits); agent e2e
    "phone cancel after the wake: PC ends as cancelled" (without the fix the
    PC reported `network`, checked by disabling it). Emulator (fake FCM): the
    PC cancelled right after the wake reached the app; the app dialed in
    about 5 s later, got `CANCELLED` and ended quietly ("receive cancelled"
    in logcat, no notice), 2 runs. Agent idle after the change: 0.81 MB
    private working set, 0 % CPU, 6 threads. Logcat now also says how a
    receive ended (`receive cancelled` / `receive failed <kind>`).
11. ✓ **Large files on the phone (2026-10-12):** the hard-coded 500 MB cap no
    longer declines silently. Items above the phone's limit (Settings → "Ask
    before receiving": 100 MB / 500 MB / 1 GB / 2 GB / never; default 500 MB)
    raise a question: a high-priority notification with Decline / Accept, and
    the same buttons on the home screen's transfer row. No answer within
    110 s declines (protocol §8.4; the sender now waits 120 s for the answer
    to `Offer`, other reads keep 30 s). The PC says why a send was refused
    ("The device declined it." / "above the device's size limit and wasn't
    accepted"; `transfer.done` codes `declined`, `not-accepted`). Tests: core
    e2e (yes, no, a mixed offer, no way to ask, a cancel from either side
    withdraws the question; an ignored 35 s test for a slow answer). Emulator
    check with the new fake FCM (dev-setup §9): accept from the notification
    (3 MB, hash equal, answered after 49 s), decline, a PC cancel while asking
    (question gone), no answer (ended after 112 s with `not-accepted`), small
    text without a question, the in-app buttons in Turkish, the settings
    dialog; no "Couldn't receive" notice after a decline or cancel. Agent
    idle after the change: 0.87 MB private working set, 0 % CPU, 6 threads. Open: the PC still
    declines above its own `ask_above_mb` without asking (needs a toast with
    buttons); on a relayed connection the "slow connection" notice can appear
    while the question is open. Real-phone check pending (phone away).
12. ✓ **A woken app sometimes never finished the receive (2026-10-12).**
    Cause: iroh's network monitor (netwatch) forks `ip route` on Android to
    find the default route; the child sometimes hung before `exec` and blocked
    the endpoint bind for good, so no timeout could fire (7 of 20 cold starts
    in the emulator). Fixed by a patched netwatch that reads the route through
    JNI (`vendor/netwatch`, WARPSHOT-PATCH.md): 0 of 20 afterwards. Details
    and numbers: spikes.md "Android bind hang". Re-check the patch on every
    iroh upgrade. Real-phone check pending (the S21 FE never showed it so far,
    but the race is timing-dependent).
13. ✓ **"New device" alert on the phone (2026-10-12, protocol §4.6).** The
    phone now alerts like the PC when another member adds a device: a
    high-priority notification and, in the app, a dialog with "This wasn't
    me" (removes the device with reason "not me", and optionally the device
    that added it as lost or stolen) or "It was me". The core reports every
    device that is new in a pulled or synced log and wasn't added by this
    phone (FFI `TransferObserver.on_device_added`,
    `Warpshot.remove_device_not_me`). Found on the way: no one sent the
    `group-changed` wake, so a phone learned about a new device only at the
    next app start or transfer; the agent and the phone now send it to the
    other members after each membership change. Also: the phone listed other
    phones as send targets ("PCs"); targets are now non-Android devices only.
    Emulator check: a simulated phone paired with the test PC while the app
    was closed; the woken app alerted within 2 s ("“Sim Phone” (Android) was
    added by MERTPC."), the dialog in Turkish, "This wasn't me" removed it
    from the group (gone from the PC's device list). Open: the PC's alert
    doesn't offer removing the adder yet.

## Security testing (attack our own app) — before wider use

Progress (2026-10-12): items 2–6, 8 and 9 done, 7 partly; results and fixes in
`docs/threat-model.md` §6.1. Next:
key-theft write-up (roadmap "Next session" 6), the rest of 7 (MobSF on the
APK, Keystore extraction in a rooted emulator).

**One batched phone session (user, 2026-10-12)** — everything that needs the
real phone, so it is connected once (~30–40 min, user hands-on ~3 min):
install the new build (`adb install -r`, data kept); large-file prompt
(decline, then accept); share-sheet PC row; Quick Settings tile (added with
`cmd statusbar add-tile`, removed afterwards); Doze (`deviceidle force-idle`)
and standby buckets, restored afterwards; 5 PC → phone wakes in a row (JNI
default-route fix); item 1 on the phone: the app's sockets at idle and during
a transfer, a stray UDP packet gets no answer; appops / standby bucket /
batterystats read-only; force-stop mid-receive → partials swept; clipboard
marked sensitive (phone) and kept out of the cloud clipboard (PC: check the
`CanUploadToCloudClipboard` format after a phone → PC text); the user shares a
gallery photo (thumbnail preview). Delete every test item on both devices.
Before it: install the new agent and measure idle (`measure-idle.ps1
-WarmupSeconds 150`). Later phone needs only: Faz 3 store build, own relay.

Mode (user, 2026-10-10): as aggressive as possible, white-box, against our
own targets only: the user's PC and phone, our Worker, our Firebase project.
Load tests stay inside our own Worker's free-tier quota; third-party
infrastructure (n0 public relays, FCM, Cloudflare edge) is not flooded —
use `wrangler dev` / a local relay for volume tests.

Attack surface today: no listening port at idle on either device (outbound
WebSocket only); the iroh UDP endpoint exists only during a transfer and
admits only verified group members; the named pipe is current-user only;
received files are saved with MOTW and never opened. Each item below gets a
written result in `docs/threat-model.md` §6.

1. **Port/exposure scan:** nmap (TCP+UDP) against PC and phone at idle and
   during a transfer; confirm nothing answers a non-member.
2. **Malicious peer:** a hostile `warpctl` variant that is (a) not a member,
   (b) a removed member, (c) a member sending bad frames: path traversal and
   reserved names, oversize/lying sizes, wrong BLAKE3, endless streams,
   replayed sessions, flood of connections. Expect refusal, no file written,
   no crash, bounded memory.
3. **Wake abuse:** replayed/forged/expired envelopes, wakes from non-members,
   FCM messages not from our server; the phone must stay silent and never
   dial an attacker-chosen address for an invalid envelope.
4. **Pairing:** expired/reused QR, wrong proof, SAS mismatch, a second
   scanner racing the first.
5. **Server API:** unauthenticated and replayed requests, other groups'
   ids, rate limits, oversized bodies, log CAS races, push-token theft;
   a compromised server must not be able to add members or read content.
6. **Local:** pipe access from another Windows user and from a non-owner
   pipe squatter; what a same-user process can do through the pipe
   (e.g. `send.files` of arbitrary paths) — decide on a confirmation.
7. **Android:** exported components (`ShareActivity` takes any share,
   `PushService`/`TransferService` not exported), MobSF static scan,
   Keystore extraction attempt on a rooted test device, clipboard leaks.
8. **Traffic check:** Wireshark/pktmon capture: no plaintext content, names
   or addresses to the server or FCM.
9. **Fuzzing + supply chain:** extend fuzz targets to every decoder
   (xfer frames, wake, pair, server JSON); `cargo deny`, `npm audit`,
   dependency review; later an external audit (Faz 3).
