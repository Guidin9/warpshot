//! Security tests, "malicious peer" (roadmap "Security testing" 2): a hostile
//! peer that is a valid, verified group member (so it gets past admission and
//! the handshake) and then breaks the transfer rules on purpose; plus
//! non-members, removed members and a connection flood at admission.
//! Every case expects a refusal, no file outside or left behind in the target
//! folder, no crash, and bounded memory (frames are size-checked before any
//! allocation).
//!
//! cargo test -p warpshot-core --features attack --test attack

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use warpshot_core::{
    log::{Op, RecordBody, RemoveReason, platform, sign_record},
    net::{
        self, NetError, Relay,
        store::{Device, now_ms},
        xfer::{self as nx, Policy, Received},
    },
    pair::{QrPayload, Window},
    xfer::{Ctrl, Item, code, kind},
};

fn tmpdir(tag: &str) -> PathBuf {
    let mut b = [0u8; 6];
    warpshot_core::keys::random(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!(
        "warpshot-attack-{tag}-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

async fn accept_conn(ep: &iroh::Endpoint) -> iroh::endpoint::Connection {
    let inc = ep.accept().await.expect("incoming");
    inc.accept().expect("accepting").await.expect("connection")
}

async fn paired() -> (Device, Device) {
    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let ep_d = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_s = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let mut window = Window::open(
        pc.id(),
        net::dial_info(&ep_d),
        pc.name.clone(),
        None,
        now_ms() / 1000,
    )
    .unwrap();
    let qr = QrPayload::parse(&window.qr_text()).unwrap();
    let (d, s) = tokio::join!(
        async {
            let conn = accept_conn(&ep_d).await;
            net::pair::display(
                &ep_d,
                conn,
                &mut window,
                &pc,
                now_ms(),
                |_| async { true },
                |_| async { Ok(()) },
            )
            .await
        },
        net::pair::scan(
            &ep_s,
            &qr,
            &phone,
            now_ms(),
            |_| async { true },
            |_| async { Ok(()) }
        )
    );
    pc.log = Some(d.unwrap().log);
    phone.log = Some(s.unwrap().log);
    ep_d.close().await;
    ep_s.close().await;
    (pc, phone)
}

/// The honest PC (listener, receiver) and the hostile phone (dialer, sender).
struct Rig {
    pc: Device,
    phone: Device,
    ep_pc: iroh::Endpoint,
    ep_phone: iroh::Endpoint,
}

impl Rig {
    async fn new() -> Self {
        let (pc, phone) = paired().await;
        let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
        let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
        Self {
            pc,
            phone,
            ep_pc,
            ep_phone,
        }
    }

    /// One honest receive into `dir` (no size limit in the way).
    async fn receive(&self, dir: &Path) -> (Vec<Received>, Result<(), NetError>) {
        let conn = accept_conn(&self.ep_pc).await;
        let s = nx::accept(&self.ep_pc, conn, self.pc.log.as_ref().unwrap())
            .await
            .unwrap();
        let policy = Policy {
            dir: dir.to_path_buf(),
            max_size: 1 << 30,
            accept_large: false,
        };
        s.receive_keep(&policy, |_| true).await
    }

    /// The hostile phone's session (admitted: it is a member).
    async fn dial(&self) -> nx::Session {
        nx::dial(
            &self.ep_phone,
            self.phone.log.as_ref().unwrap(),
            &self.pc.id(),
            &net::dial_info(&self.ep_pc),
            [0; 16],
        )
        .await
        .unwrap()
    }

    async fn close(self) {
        self.ep_pc.close().await;
        self.ep_phone.close().await;
    }
}

fn file_item(id: u32, name: &str, size: u64) -> Item {
    Item {
        id,
        kind: kind::FILE,
        name: name.into(),
        mime: "application/octet-stream".into(),
        size,
        created_at: 0,
        text: None,
    }
}

/// Offers `items` and waits for the receiver's answer.
async fn offer(s: &mut nx::Session, items: Vec<Item>) -> Ctrl {
    s.send_ctrl(&Ctrl::Offer {
        session: [0; 16],
        items,
    })
    .await
    .unwrap();
    s.recv_ctrl().await.unwrap()
}

const CHUNK: usize = 64 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_data_than_declared_is_cut_off() {
    let rig = Rig::new().await;

    // One last chunk of 5000 bytes for an item declared as 1000.
    let dir = tmpdir("more");
    let (r, ()) = tokio::join!(rig.receive(&dir), async {
        let mut s = rig.dial().await;
        assert!(matches!(
            offer(&mut s, vec![file_item(1, "a.bin", 1000)]).await,
            Ctrl::Accept { .. }
        ));
        let _ = s.attack_stream(1, &[(vec![7; 5000], true)]).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), s.conn.closed()).await;
    });
    assert!(r.1.is_err(), "oversize stream accepted: {:?}", r.1);
    assert!(r.0.is_empty());
    assert!(
        files_in(&dir).is_empty(),
        "left behind: {:?}",
        files_in(&dir)
    );

    // An endless stream (full chunks, never "last") for an item declared as
    // 100 000 bytes: the receiver stops after the second chunk.
    let dir = tmpdir("endless");
    let t0 = Instant::now();
    let (r, ()) = tokio::join!(rig.receive(&dir), async {
        let mut s = rig.dial().await;
        assert!(matches!(
            offer(&mut s, vec![file_item(1, "b.bin", 100_000)]).await,
            Ctrl::Accept { .. }
        ));
        let chunks: Vec<(Vec<u8>, bool)> = (0..200).map(|_| (vec![1; CHUNK], false)).collect();
        let _ = s.attack_stream(1, &chunks).await;
    });
    assert!(matches!(r.1, Err(NetError::TooLarge)), "{:?}", r.1);
    assert!(
        files_in(&dir).is_empty(),
        "left behind: {:?}",
        files_in(&dir)
    );
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "took {:?}",
        t0.elapsed()
    );
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_data_or_wrong_hash_is_not_saved() {
    let rig = Rig::new().await;
    for (what, data_len, done_size, wrong_hash) in [
        ("short", 1000usize, 5000u64, false),
        ("lying-done", 1000, 1000, true),
    ] {
        let dir = tmpdir(what);
        let declared = done_size;
        let (r, ack) = tokio::join!(rig.receive(&dir), async {
            let mut s = rig.dial().await;
            assert!(matches!(
                offer(&mut s, vec![file_item(1, "c.bin", declared)]).await,
                Ctrl::Accept { .. }
            ));
            let data = vec![9u8; data_len];
            s.attack_stream(1, &[(data.clone(), true)]).await.unwrap();
            let hash = if wrong_hash {
                [0u8; 32]
            } else {
                *blake3::hash(&data).as_bytes()
            };
            s.send_ctrl(&Ctrl::ItemDone {
                id: 1,
                blake3: hash,
                size: done_size,
            })
            .await
            .unwrap();
            let ack = s.recv_ctrl().await;
            let _ = s.send_ctrl(&Ctrl::Bye).await;
            ack
        });
        assert!(
            matches!(ack, Ok(Ctrl::ItemAck { ok: false, .. })),
            "{what}: {ack:?}"
        );
        assert!(r.0.is_empty(), "{what}: reported as saved");
        assert!(
            files_in(&dir).is_empty(),
            "{what}: left behind: {:?}",
            files_in(&dir)
        );
    }
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_for_another_item_is_refused() {
    let rig = Rig::new().await;
    let dir = tmpdir("otherid");
    let (r, ()) = tokio::join!(rig.receive(&dir), async {
        let mut s = rig.dial().await;
        assert!(matches!(
            offer(&mut s, vec![file_item(1, "d.bin", 10)]).await,
            Ctrl::Accept { .. }
        ));
        let _ = s.attack_stream(7, &[(vec![0; 10], true)]).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), s.conn.closed()).await;
    });
    assert!(r.1.is_err(), "{:?}", r.1);
    assert!(
        files_in(&dir).is_empty(),
        "left behind: {:?}",
        files_in(&dir)
    );
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_control_frames_are_refused_at_once() {
    let rig = Rig::new().await;
    // A frame header announcing 4 GiB: refused before any allocation.
    // Garbage that fails authentication: refused (CRYPTO).
    let mut garbage = 64u32.to_be_bytes().to_vec();
    garbage.extend([0x5a; 64]);
    for (what, bytes) in [
        ("huge", u32::MAX.to_be_bytes().to_vec()),
        ("garbage", garbage),
    ] {
        let dir = tmpdir(what);
        let t0 = Instant::now();
        let (r, ()) = tokio::join!(rig.receive(&dir), async {
            let mut s = rig.dial().await;
            s.attack_raw_ctrl(&bytes).await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(10), s.conn.closed()).await;
        });
        assert!(r.1.is_err(), "{what}: {:?}", r.1);
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "{what}: took {:?}",
            t0.elapsed()
        );
        assert!(files_in(&dir).is_empty());
    }
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_many_items_are_refused() {
    let rig = Rig::new().await;
    let dir = tmpdir("many");
    let items: Vec<Item> = (1..=1001).map(|i| file_item(i, "x", 1)).collect();
    let (r, ()) = tokio::join!(rig.receive(&dir), async {
        let mut s = rig.dial().await;
        let _ = s
            .send_ctrl(&Ctrl::Offer {
                session: [0; 16],
                items,
            })
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(10), s.conn.closed()).await;
    });
    assert!(r.1.is_err(), "{:?}", r.1);
    assert!(files_in(&dir).is_empty());
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_names_stay_inside_the_folder() {
    let rig = Rig::new().await;
    let parent = tmpdir("names");
    let dir = parent.join("in");
    std::fs::create_dir_all(&dir).unwrap();
    let names = [
        "../../escape.txt",
        "..\\..\\escape2.txt",
        "C:\\Windows\\evil.dll",
        "/etc/passwd",
        "CON",
        "nul.txt",
        "invoice\u{202E}fdp.exe",
        "a:stream",
        "trailing. ",
        "",
        "..",
    ];
    let items: Vec<Item> = names
        .iter()
        .enumerate()
        .map(|(i, n)| file_item(i as u32 + 1, n, 3))
        .collect();
    let (r, ()) = tokio::join!(rig.receive(&dir), async {
        let mut s = rig.dial().await;
        assert!(matches!(
            offer(&mut s, items.clone()).await,
            Ctrl::Accept { .. }
        ));
        for it in &items {
            let data = b"abc".to_vec();
            s.attack_stream(it.id, &[(data.clone(), true)])
                .await
                .unwrap();
            s.send_ctrl(&Ctrl::ItemDone {
                id: it.id,
                blake3: *blake3::hash(&data).as_bytes(),
                size: 3,
            })
            .await
            .unwrap();
            assert!(matches!(
                s.recv_ctrl().await.unwrap(),
                Ctrl::ItemAck { ok: true, .. }
            ));
        }
        s.send_ctrl(&Ctrl::Bye).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.conn.closed()).await;
    });
    r.1.unwrap();
    assert_eq!(r.0.len(), names.len());
    assert_eq!(
        files_in(&parent),
        vec!["in".to_string()],
        "something escaped the folder"
    );
    let saved = files_in(&dir);
    assert_eq!(saved.len(), names.len(), "{saved:?}");
    for n in &saved {
        assert!(
            !n.contains(['/', '\\', ':', '\u{202E}']),
            "unsafe name kept: {n:?}"
        );
        let stem = n.split('.').next().unwrap_or_default().to_ascii_uppercase();
        assert!(
            !["CON", "NUL"].contains(&stem.as_str()),
            "reserved name kept: {n:?}"
        );
        assert!(
            !n.ends_with('.') && !n.ends_with(' '),
            "trailing dot/space kept: {n:?}"
        );
    }
    // Apps (notifications, history, MediaStore) get the saved names, never the raw ones.
    let mut reported: Vec<String> = r.0.iter().map(|x| x.item.name.clone()).collect();
    reported.sort();
    assert_eq!(reported, saved);
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_peer_times_out_at_the_handshake() {
    let rig = Rig::new().await;
    // A member that connects and then says nothing (no Hello).
    let t0 = Instant::now();
    let (pc_id, pc_addr) = (rig.pc.id(), net::dial_info(&rig.ep_pc));
    let (acc, _conn) = tokio::join!(
        async {
            let conn = accept_conn(&rig.ep_pc).await;
            nx::accept(&rig.ep_pc, conn, rig.pc.log.as_ref().unwrap()).await
        },
        net::connect(&rig.ep_phone, &pc_id, &pc_addr, warpshot_core::xfer::ALPN)
    );
    assert!(matches!(acc, Err(NetError::Timeout)), "{acc:?}");
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "took {:?}",
        t0.elapsed()
    );
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_members_and_removed_members_are_refused_at_admission() {
    let (mut pc, phone) = paired().await;
    let stranger = Device::new("stranger", platform::ANDROID).unwrap();
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_x = net::bind(&stranger.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let pc_addr = net::dial_info(&ep_pc);
    let pc_id = pc.id();

    // A stranger that claims the PC's log as its own.
    let (acc, dial) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            nx::accept(&ep_pc, conn, pc.log.as_ref().unwrap())
                .await
                .map(|_| ())
        },
        nx::dial(&ep_x, pc.log.as_ref().unwrap(), &pc_id, &pc_addr, [0; 16])
    );
    assert_eq!(acc.unwrap_err(), NetError::Identity);
    assert!(dial.is_err());

    // The phone is removed as lost or stolen; its keys still work, its access doesn't.
    let mut log = pc.log.clone().unwrap();
    let (seq, prev) = log.next_position();
    let raw = sign_record(
        &pc.keys.ik,
        &RecordBody {
            group_id: log.group_id(),
            seq,
            prev,
            created_at: now_ms(),
            subject: phone.id(),
            op: Op::Remove(RemoveReason::LostOrStolen),
        },
    );
    log.append(&raw, now_ms()).unwrap();
    pc.log = Some(log);
    let (acc, dial) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            nx::accept(&ep_pc, conn, pc.log.as_ref().unwrap())
                .await
                .map(|_| ())
        },
        // The removed phone still has the old log, in which it is a member.
        nx::dial(
            &ep_phone,
            phone.log.as_ref().unwrap(),
            &pc_id,
            &pc_addr,
            [0; 16]
        )
    );
    assert_eq!(acc.unwrap_err(), NetError::Identity);
    assert!(dial.is_err());

    // A record signed by the removed phone is refused by the log.
    let mut log = pc.log.clone().unwrap();
    let (seq, prev) = log.next_position();
    let forged = sign_record(
        &phone.keys.ik,
        &RecordBody {
            group_id: log.group_id(),
            seq,
            prev,
            created_at: now_ms(),
            subject: stranger.id(),
            op: Op::Remove(RemoveReason::User),
        },
    );
    assert!(
        log.append(&forged, now_ms()).is_err(),
        "removed device signed a record"
    );

    for ep in [ep_pc, ep_x, ep_phone] {
        ep.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_flood_from_a_stranger_does_not_block_a_member() {
    use warpshot_core::net::dispatch::Dispatcher;
    let (pc, phone) = paired().await;
    let stranger = Device::new("stranger", platform::ANDROID).unwrap();
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let pc_addr = net::dial_info(&ep_pc);
    let pc_log = pc.log.clone().unwrap();
    let disp = Dispatcher::new();
    let mut wait = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();

    // 200 connection attempts from a non-member, 20 endpoints x 10 each.
    let t0 = Instant::now();
    let mut flood = Vec::new();
    for _ in 0..20 {
        let ik = Device::new("x", platform::ANDROID).unwrap();
        let ep = net::bind(&ik.keys.ik, Relay::Disabled).await.unwrap();
        let (log, id, addr) = (stranger.log.clone(), pc.id(), pc_addr.clone());
        let pc_log = pc_log.clone();
        flood.push(tokio::spawn(async move {
            let mut refused = 0;
            for _ in 0..10 {
                let r = nx::dial(&ep, log.as_ref().unwrap_or(&pc_log), &id, &addr, [3; 16]).await;
                if r.is_err() {
                    refused += 1;
                }
            }
            ep.close().await;
            refused
        }));
    }
    // Meanwhile the member dials in with its session and the transfer goes through.
    let session = wait.session();
    let (got, sent) = tokio::join!(
        async {
            let mut log = phone.log.clone().unwrap();
            let mut s = net::flow::answer_connect(&ep_phone, &log, &pc.id(), session, &pc_addr)
                .await
                .unwrap();
            s.sync_logs(&mut log, now_ms()).await.unwrap();
            let policy = Policy {
                dir: tmpdir("flood"),
                max_size: 1 << 30,
                accept_large: false,
            };
            s.receive(&policy, |_| true).await
        },
        async {
            let mut s = wait.arrived().await.unwrap();
            s.sync_logs(&mut pc_log.clone(), now_ms()).await.unwrap();
            s.send_items(vec![nx::text_item(1, "still works", now_ms()).unwrap()])
                .await
        }
    );
    assert_eq!(sent.unwrap(), vec![(1, true)]);
    assert_eq!(got.unwrap()[0].item.text.as_deref(), Some("still works"));
    let mut refused = 0;
    for f in flood {
        refused += f.await.unwrap();
    }
    assert_eq!(refused, 200, "a stranger got in");
    eprintln!(
        "flood: 200 refused, member transfer done, {:?}",
        t0.elapsed()
    );
    let _ = code::PROTOCOL;
    ep_pc.close().await;
    ep_phone.close().await;
}

// ---------------------------------------------------------------- pairing (plan item 4)

/// One pairing attempt: the PC shows `window`, `scanner` uses `qr`.
async fn pair_attempt(
    pc: &Device,
    window: &mut Window,
    scanner: &Device,
    qr: &QrPayload,
    pc_says: bool,
    scanner_says: bool,
) -> (
    Result<net::pair::Paired, NetError>,
    Result<net::pair::Paired, NetError>,
) {
    let ep_d = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_s = net::bind(&scanner.keys.ik, Relay::Disabled).await.unwrap();
    let mut qr = qr.clone();
    qr.dial = net::dial_info(&ep_d);
    let r = tokio::join!(
        async {
            // A scanner that refuses locally never connects: give up after a while.
            let conn = tokio::time::timeout(Duration::from_secs(15), accept_conn(&ep_d))
                .await
                .map_err(|_| NetError::Timeout)?;
            net::pair::display(
                &ep_d,
                conn,
                window,
                pc,
                now_ms(),
                |_| async move { pc_says },
                |_| async { Ok(()) },
            )
            .await
        },
        net::pair::scan(
            &ep_s,
            &qr,
            scanner,
            now_ms(),
            |_| async move { scanner_says },
            |_| async { Ok(()) }
        )
    );
    ep_d.close().await;
    ep_s.close().await;
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_attacks_are_refused() {
    let pc = Device::new("pc", platform::WINDOWS).unwrap();
    let phone = Device::new("phone", platform::ANDROID).unwrap();
    let dial = net::dial_info(&net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap());
    let fresh = |secs_ago: u64| {
        Window::open(
            pc.id(),
            dial.clone(),
            pc.name.clone(),
            None,
            now_ms() / 1000 - secs_ago,
        )
        .unwrap()
    };

    eprintln!("case expired");
    // A QR code past its 120 s window.
    let mut w = fresh(200);
    let qr = QrPayload::parse(&w.qr_text()).unwrap();
    let (d, s) = pair_attempt(&pc, &mut w, &phone, &qr, true, true).await;
    assert!(d.is_err() && s.is_err(), "expired QR paired: {d:?} / {s:?}");
    // The same with a scanner that ignores the expiry (rewrites it): the PC refuses.
    let mut qr = QrPayload::parse(&w.qr_text()).unwrap();
    qr.exp = now_ms() / 1000 + 100;
    let (d, s) = pair_attempt(&pc, &mut w, &phone, &qr, true, true).await;
    assert!(
        matches!(
            d,
            Err(NetError::Pair(warpshot_core::pair::PairError::Expired))
        ) && s.is_err(),
        "PC paired with an expired window: {d:?} / {s:?}"
    );

    eprintln!("case proof");
    // A scanner that guessed the rest of the code but not the secret (wrong proof).
    let mut w = fresh(0);
    let mut qr = QrPayload::parse(&w.qr_text()).unwrap();
    let mut guess = [0u8; 32];
    warpshot_core::keys::random(&mut guess).unwrap();
    qr.secret = guess.into();
    let (d, s) = pair_attempt(&pc, &mut w, &phone, &qr, true, true).await;
    assert!(
        d.is_err() && s.is_err(),
        "wrong proof paired: {d:?} / {s:?}"
    );

    eprintln!("case sas");
    // The codes didn't match: whichever side says no, nobody joins.
    for (pc_says, phone_says) in [(false, true), (true, false)] {
        let mut w = fresh(0);
        let qr = QrPayload::parse(&w.qr_text()).unwrap();
        let (d, s) = pair_attempt(&pc, &mut w, &phone, &qr, pc_says, phone_says).await;
        assert!(
            d.is_err() && s.is_err(),
            "SAS refused ({pc_says}/{phone_says}) but paired"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_scanners_racing_for_one_code_only_one_joins() {
    let pc = Device::new("pc", platform::WINDOWS).unwrap();
    let a = Device::new("phone-a", platform::ANDROID).unwrap();
    let b = Device::new("phone-b", platform::ANDROID).unwrap();
    let ep_d = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_a = net::bind(&a.keys.ik, Relay::Disabled).await.unwrap();
    let ep_b = net::bind(&b.keys.ik, Relay::Disabled).await.unwrap();
    let mut window = Window::open(
        pc.id(),
        net::dial_info(&ep_d),
        pc.name.clone(),
        None,
        now_ms() / 1000,
    )
    .unwrap();
    let qr = QrPayload::parse(&window.qr_text()).unwrap();
    let (displays, sa, sb) = tokio::join!(
        async {
            // The PC takes both connections one after the other on the same window.
            let mut out = Vec::new();
            for _ in 0..2 {
                let conn = accept_conn(&ep_d).await;
                out.push(
                    net::pair::display(
                        &ep_d,
                        conn,
                        &mut window,
                        &pc,
                        now_ms(),
                        |_| async { true },
                        |_| async { Ok(()) },
                    )
                    .await
                    .is_ok(),
                );
            }
            out
        },
        net::pair::scan(
            &ep_a,
            &qr,
            &a,
            now_ms(),
            |_| async { true },
            |_| async { Ok(()) }
        ),
        net::pair::scan(
            &ep_b,
            &qr,
            &b,
            now_ms(),
            |_| async { true },
            |_| async { Ok(()) }
        )
    );
    let joined = [sa.is_ok(), sb.is_ok()].iter().filter(|x| **x).count();
    assert_eq!(
        displays.iter().filter(|x| **x).count(),
        1,
        "PC paired {displays:?}"
    );
    assert_eq!(
        joined,
        1,
        "scanners joined: a={} b={}",
        sa.is_ok(),
        sb.is_ok()
    );
    for ep in [ep_d, ep_a, ep_b] {
        ep.close().await;
    }
}

// ---------------------------------------------------------------- compromised server (plan item 5)

/// Signs `op` on `subject` with `signer` as the next record of `log`.
fn next_record(
    log: &warpshot_core::log::Log,
    signer: &Device,
    subject: &Device,
    op: Op,
) -> Vec<u8> {
    let (seq, prev) = log.next_position();
    sign_record(
        &signer.keys.ik,
        &RecordBody {
            group_id: log.group_id(),
            seq,
            prev,
            created_at: now_ms(),
            subject: subject.id(),
            op,
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compromised_server_cannot_change_the_group() {
    use warpshot_core::net::server::apply;
    let (pc, phone) = paired().await;
    let attacker = Device::new("attacker", platform::WINDOWS).unwrap();
    let mine = phone.log.clone().unwrap();
    let head = |l: &warpshot_core::log::Log| l.head().unwrap();
    let members = |l: &warpshot_core::log::Log| l.members().len();

    // The server adds the attacker's own device, signed by the attacker.
    let mut log = mine.clone();
    let forged = next_record(&mine, &attacker, &attacker, Op::Add(attacker.info()));
    assert!(apply(&mut log, &[forged.clone()], &head(&mine), now_ms()).is_err());
    assert_eq!(members(&log), 2);
    assert!(!log.is_member(&attacker.id()));

    // A record signed by a device the group removed.
    let mut pc_view = pc.log.clone().unwrap();
    let removal = next_record(
        &pc_view,
        &pc,
        &phone,
        Op::Remove(RemoveReason::LostOrStolen),
    );
    pc_view.append(&removal, now_ms()).unwrap();
    let mut log = pc_view.clone();
    let by_removed = next_record(&pc_view, &phone, &attacker, Op::Add(attacker.info()));
    assert!(apply(&mut log, &[by_removed], &head(&pc_view), now_ms()).is_err());
    assert!(!log.is_member(&attacker.id()));

    // History rewritten: another record at a seq we already have is a fork.
    let mut log = mine.clone();
    let mut older = mine.clone();
    let _ = &mut older;
    let rewrite = {
        // The same position as our last record, different content (signed by a member).
        let recs = mine.records();
        let last = recs.last().unwrap();
        sign_record(
            &pc.keys.ik,
            &RecordBody {
                group_id: mine.group_id(),
                seq: last.body.seq,
                prev: last.body.prev,
                created_at: now_ms(),
                subject: attacker.id(),
                op: Op::Add(attacker.info()),
            },
        )
    };
    assert_eq!(
        apply(&mut log, &[rewrite], &head(&mine), now_ms()).unwrap_err(),
        NetError::Fork
    );
    assert!(!log.is_member(&attacker.id()));

    // A gap (records withheld) is refused; old records sent again change nothing.
    let mut ahead = pc_view.clone();
    let skipped = next_record(&ahead, &pc, &attacker, Op::Add(attacker.info()));
    ahead.append(&skipped, now_ms()).unwrap();
    let mut log = mine.clone();
    let only_last = ahead.records().last().unwrap().raw.clone();
    assert!(apply(&mut log, &[only_last], &head(&ahead), now_ms()).is_err());
    assert_eq!(log.head(), mine.head());
    let mut log = mine.clone();
    let replay: Vec<Vec<u8>> = mine.records().iter().map(|r| r.raw.clone()).collect();
    assert!(!apply(&mut log, &replay, &head(&mine), now_ms()).unwrap());
    assert_eq!(log.head(), mine.head());
}
