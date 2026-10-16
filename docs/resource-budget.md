# Windows agent resource budget

The user's explicit requirement: when idle in the background, `warpshot-agent.exe` must
use as few resources as possible — RAM especially, and the network almost not at
all. This budget is an **acceptance gate**. A change that breaks it does not merge.

## 1. Budget

"Idle" means the agent has been running for at least 10 minutes since the last
transfer or UI interaction, the network is connected, and `warpshot-ui.exe` is closed.

| Metric | Budget | How it is measured |
|---|---|---|
| Private working set (Task Manager "Memory" column) | **< 5 MB** | WMI `Win32_PerfFormattedData_PerfProc_Process.WorkingSetPrivate` (locale-independent) |
| Private bytes (commit) | < 12 MB | `Process.PrivateMemorySize64` |
| CPU | ≈ 0 (< 0.05 % average over 10 min) | `Process.TotalProcessorTime` delta |
| Threads | ≤ 6 (our 2 + OS-created pool/loader threads) | `Process.Threads.Count` |
| Handles | stable (no growth across samples) | `Process.HandleCount` |
| Network | **< 0.5 MB/day** (projected from 10 min) | the agent's own socket byte counters (debug IPC), cross-checked with `pktmon` |
| Timers while idle | 1 (the WebSocket keepalive, period K ≥ 60 s) | code review + ETW (optional) |

Expected network at idle: one TLS WebSocket to Cloudflare with an app-level ping
every 60–90 s, about 200 bytes per round trip including TCP/IP overhead, which
comes to ≈ 0.2–0.3 MB/day. Spike C fixes K.

## 2. Design rules for `warpshot-agent.exe`

1. **Two threads.** The Win32 message loop, plus one tokio `current_thread`
   runtime that holds the server WebSocket and the named-pipe listener. Nothing
   else runs at idle. Connections to the server use a blocking connect on the
   blocking pool: a non-blocking one starts Winsock's own helper thread for
   five minutes (§4, 2026-10-16).
2. **Event-driven only.** No polling. The single idle timer is the WebSocket keepalive.
3. **P2P on demand.** The iroh endpoint and transfer tasks start when needed and
   stop after 30 s without work. Any extra runtime threads end with them.
4. **No WebView or Tauri in the agent.** The settings UI is a separate process that exits when closed.
5. **Lazy OS subsystems.** WinRT/COM objects for toasts, image codecs and the
   clipboard are created on use and released afterwards. Do not keep a
   `ToastNotifier` alive.
6. **Bounded buffers.** Files are streamed (64 KiB chunks); whole-file buffers
   are never used. Clipboard images are the only full in-memory payload, and they
   are dropped right after sending. Large `Vec`s are released (not just cleared)
   after a transfer.
7. **Trim after work.** After endpoint teardown, call
   `SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX)` to
   release pages back to the OS.
8. **Power:** EcoQoS (`SetProcessInformation(ProcessPowerThrottling)`) while idle;
   normal QoS during a transfer so it stays fast.
9. **Storage on demand.** SQLite is opened when needed, with a small `cache_size`,
   and closed when idle. The log file is opened in append mode per write; there
   is no flush timer.
10. **Release profile.** `opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`,
    `panic = "abort"`, `strip = true`. A smaller image means fewer touched pages.
11. **Dependency review.** Reject crates that start background threads or timers
    at init (some loggers, file watchers, metrics). Check this for every new dependency.

## 3. Measuring

```powershell
# After the agent has been idle ≥ 1 min; samples every 5 s for 10 min
powershell -ExecutionPolicy Bypass -File scripts\measure-idle.ps1 -ProcessName warpshot-agent
# Exit code 1 if over budget (used as a CI gate on the Windows runner)
# Which threads come and go, with names and start modules (read-only):
powershell -ExecutionPolicy Bypass -File scripts\watch-threads.ps1 -ProcessId (Get-Process warpshot-agent).Id -Seconds 600
```

Network cross-check with `pktmon` (requires admin):

```powershell
$rip = (Get-NetTCPConnection -OwningProcess (Get-Process warpshot-agent).Id -State Established).RemoteAddress
pktmon filter remove; pktmon filter add PT -i $rip
pktmon start --capture --pkt-size 0 --file-name idle.etl   # wait 10 min
pktmon stop; pktmon etl2txt idle.etl -o idle.txt         # sum the packet lengths
```

## 4. Results

| Date | Commit | Build | Private WS | Commit | Threads | CPU % | Net (proj./day) | Notes |
|---|---|---|---|---|---|---|---|---|
| 2026-10-09 | Spike B (`spikes/agent-skeleton`) | release, 1.2 MB exe | 0.69 MB max | 1.89 MB max | 5 max | 0 | ≈ 78 KB TLS payload, ≈ 250 KB with TCP/IP headers (K = 60 s) | tray + hotkey + hibernating-DO WebSocket over rustls/ring, EcoQoS, trim after connect; 10 min of samples after 60 s warm-up |
| 2026-10-09 | agent wired to core (W1–W7) | release, 5.6 MB exe | 1.68 MB max | 3.86 MB max | 6 steady, 9 max | 0.0004 | K = 120 s: 4 pings in 8 min | paired, WS to local `wrangler dev`, after pairing + 2 receives + 1 send. Without any iroh use: max 6, settles at 3. **Open:** after the iroh endpoint closes, OS thread-pool workers come and go (up to 9); suspect iroh's network-change registration outliving the endpoint. CPU stays ≈ 0. |
| 2026-10-12 | large-file question (roadmap "Next session" 11) | release, 5.4 MB exe | 0.87 MB max | 2.26 MB max | 6 max | 0 | – (1 TCP to the server) | installed agent, paired with the real group, fresh start, no transfers; 10 min of samples after 60 s warm-up |
| 2026-10-12 | one accept loop per endpoint (roadmap "Next session" 10) | release | 0.81 MB max | 2.24 MB max | 6 max | 0 | – (1 TCP to the server) | installed agent, fresh start, no transfers; 10 min of samples after 60 s warm-up |
| 2026-10-12 | blocking pool capped (1 thread, 1 s keep-alive) + server DNS reused | release | 0.80 MB max | 2.22 MB max | 5 max (20 min); 6 max during start-up incl. DNS | 0.0001 | – (1 TCP) | before the cap a WebSocket reconnect briefly reached 8 threads (tokio's blocking pool, 10 s keep-alive); no reconnect happened in this 20 min run |
| 2026-10-16 | pairing recovery, revocation, send progress flyout | release | 0.89 MB max | 2.33 MB max | **7 max — over** | 0 | – (1 TCP) | installed agent, fresh start, no transfers, 150 s warm-up. Over budget by Winsock's `SockAsyncThread` (below) on top of OS thread-pool workers |
| 2026-10-16 | blocking server connect | release | 0.85 MB max | 2.25 MB max | 5 max | 0 | – (1 TCP) | same conditions; `scripts/watch-threads.ps1`: our 2 threads plus OS thread-pool workers only, no `SockAsyncThread` |

**Where the extra threads come from (2026-10-16).** Watched with
`scripts/watch-threads.ps1` (thread names and start modules) and reproduced in
a minimal test process that does one operation and then idles:

- Every process starts with 3 loader workers (`ntdll` thread pool); they end
  30–60 s later.
- After the first DNS lookup or DPAPI call, Windows runs its own timers on the
  thread pool: 2 workers at +30 s, 3 at +300 s, 2 at +600 s, each living
  70–100 s. Nothing in our code triggers them, and they end by themselves.
- A **non-blocking TCP connect** (tokio/mio, and std's `connect_timeout`)
  makes Winsock start `mswsock!SockAsyncThread`, which stays for five
  minutes. A plain blocking connect does not, and neither does using the
  connected socket from tokio afterwards. The server client therefore resolves
  and connects with blocking calls on tokio's blocking pool (one thread, ends a
  second later) and hands the socket to tokio (`client/transport.rs`).

Peak at idle now: our 2 + 3 pool workers = 5. Still open: after a transfer,
iroh's relay connection is a non-blocking connect (its `SockAsyncThread` stays
5 min), and a slow-route or failure toast initialises COM for the rest of the
process's life (`combase` worker threads come and go).
