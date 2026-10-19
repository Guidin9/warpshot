//! In-process end-to-end test: two iroh endpoints over loopback (no relay, no
//! server): pairing (§5) then transfers in both roles (§8).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use warpshot_core::{
    log::platform,
    net::{
        self, Relay,
        store::{Device, now_ms},
        xfer::{self as nx, OutItem, Policy, Source},
    },
    pair::{QrPayload, Window},
    xfer::{Item, kind},
};

fn tmpdir(tag: &str) -> PathBuf {
    let mut b = [0u8; 6];
    warpshot_core::keys::random(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!(
        "warpshot-e2e-{tag}-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn accept_conn(ep: &iroh::Endpoint) -> iroh::endpoint::Connection {
    let inc = ep.accept().await.expect("incoming");
    inc.accept().expect("accepting").await.expect("connection")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_then_transfer_both_ways() {
    let mut pc = Device::new("desk-pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    assert_eq!(
        net::endpoint_id(&ep_pc),
        pc.id(),
        "iroh id must equal our Ed25519 id"
    );

    // --- Pairing: the PC shows a QR, the phone scans it.
    let mut window = Window::open(
        pc.id(),
        net::dial_info(&ep_pc),
        pc.name.clone(),
        None,
        now_ms() / 1000,
    )
    .unwrap();
    let qr = QrPayload::parse(&window.qr_text()).unwrap();
    let (sas_tx, sas_rx) = tokio::sync::oneshot::channel::<String>();
    let display = async {
        let conn = accept_conn(&ep_pc).await;
        net::pair::display(
            &ep_pc,
            conn,
            &mut window,
            &pc,
            now_ms(),
            |s| async move {
                let _ = sas_tx.send(s.sas);
                true
            },
            |recs| async move {
                assert_eq!(recs.len(), 2, "genesis + add");
                Ok(())
            },
        )
        .await
    };
    let scan = net::pair::scan(
        &ep_phone,
        &qr,
        &phone,
        now_ms(),
        |_| async { true },
        |_| async { Ok(()) },
    );
    let (d, s) = tokio::join!(display, scan);
    let (d, s) = (d.unwrap(), s.unwrap());
    let sas_pc = sas_rx.await.unwrap();
    assert_eq!(sas_pc.len(), 7);
    assert_eq!(d.log.head(), s.log.head());
    assert!(d.log.is_member(&phone.id()) && d.log.is_member(&pc.id()));
    pc.log = Some(d.log);
    phone.log = Some(s.log);

    // A second scan of the same QR is refused (single use).
    let again = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            net::pair::display(
                &ep_pc,
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
            &ep_phone,
            &qr,
            &phone,
            now_ms(),
            |_| async { true },
            |_| async { Ok(()) }
        )
    );
    assert!(again.0.is_err() && again.1.is_err());

    // --- Transfer 1: phone dials the PC and sends (session all-zero → dialer offers).
    let dir_pc = tmpdir("pc");
    let file_src = tmpdir("src").join("../../evil name?.png");
    let file_src = file_src.parent().unwrap().join("evil name?.png");
    let big: Vec<u8> = (0..(64 * 1024 * 3)).map(|i| (i * 7) as u8).collect(); // exact multiple of 64 KiB
    let photo: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
    let src_path = std::env::temp_dir().join(format!("warpshot-src-{}.png", now_ms()));
    std::fs::write(&src_path, &photo).unwrap();
    let _ = file_src;
    let mut file = nx::file_item(3, &src_path, now_ms()).unwrap();
    file.item.name = "../../evil name?.png".into();
    let items = vec![
        nx::text_item(1, "merhaba dünya", now_ms()).unwrap(),
        OutItem {
            item: Item {
                id: 2,
                kind: kind::FILE,
                name: "CON.bin".into(),
                mime: "application/octet-stream".into(),
                size: big.len() as u64,
                created_at: now_ms(),
                text: None,
            },
            source: Source::Bytes(big.clone()),
        },
        file,
    ];
    let policy = Policy {
        dir: dir_pc.clone(),
        max_size: 500 << 20,
        accept_large: false,
    };
    let pc_log = pc.log.clone().unwrap();
    let phone_log = phone.log.clone().unwrap();
    let recv = async {
        let conn = accept_conn(&ep_pc).await;
        let s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
        s.receive(&policy, |_| true).await
    };
    let send = async {
        let s = nx::dial(
            &ep_phone,
            &phone_log,
            &pc.id(),
            &net::dial_info(&ep_pc),
            [0; 16],
        )
        .await
        .unwrap();
        net::require_direct(&s.conn, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        let conn = s.conn.clone();
        // Direct all the way: the slow-route alert must stay silent.
        let (out, route) = net::watch_route(
            &conn,
            std::time::Duration::from_millis(1),
            s.send_items(items),
            || panic!("slow alert on a direct path"),
        )
        .await;
        assert_eq!(
            route,
            net::Route {
                ever_direct: true,
                slow: false
            }
        );
        out
    };
    let (r, s) = tokio::join!(recv, send);
    let (r, s) = (r.unwrap(), s.unwrap());
    assert_eq!(s, vec![(1, true), (2, true), (3, true)]);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].item.text.as_deref(), Some("merhaba dünya"));
    let p2 = r[1].path.clone().unwrap();
    assert_eq!(p2.file_name().unwrap().to_str().unwrap(), "_CON.bin");
    assert_eq!(r[1].item.name, "_CON.bin", "apps see the saved name");
    assert_eq!(std::fs::read(&p2).unwrap(), big);
    let p3 = r[2].path.clone().unwrap();
    assert_eq!(p3.parent().unwrap(), dir_pc.as_path(), "no path traversal");
    assert_eq!(p3.file_name().unwrap().to_str().unwrap(), "evil name.png");
    assert_eq!(
        r[2].item.name, "evil name.png",
        "never the sender's raw name"
    );
    assert_eq!(std::fs::read(&p3).unwrap(), photo);
    #[cfg(windows)]
    {
        let mut ads = p3.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        assert!(
            std::fs::read_to_string(PathBuf::from(ads))
                .unwrap()
                .contains("ZoneId=3")
        );
    }
    assert!(
        std::fs::read_dir(&dir_pc).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".part"))
    );

    // --- Transfer 2: PC dials the phone, phone declines by policy (too large).
    let dir_phone = tmpdir("phone");
    let small_policy = Policy {
        dir: dir_phone.clone(),
        max_size: 10,
        accept_large: false,
    };
    let big_item = vec![OutItem {
        item: Item {
            id: 9,
            kind: kind::FILE,
            name: "x".into(),
            mime: "a/b".into(),
            size: 11,
            created_at: 0,
            text: None,
        },
        source: Source::Bytes(vec![0; 11]),
    }];
    let (r, s) = tokio::join!(
        async {
            let conn = accept_conn(&ep_phone).await;
            nx::accept(&ep_phone, conn, &phone_log)
                .await
                .unwrap()
                .receive(&small_policy, |_| true)
                .await
        },
        async {
            nx::dial(
                &ep_pc,
                &pc_log,
                &phone.id(),
                &net::dial_info(&ep_phone),
                [0; 16],
            )
            .await
            .unwrap()
            .send_items(big_item)
            .await
        }
    );
    assert_eq!(r.unwrap(), vec![]);
    assert_eq!(
        s.unwrap_err(),
        net::NetError::Declined(warpshot_core::xfer::decline::TOO_LARGE)
    );

    // --- A non-member is refused at admission.
    let stranger = Device::new("stranger", platform::WINDOWS).unwrap();
    let ep_x = net::bind(&stranger.keys.ik, Relay::Disabled).await.unwrap();
    let mut fake_log = pc_log.clone();
    // The stranger pretends PC is in its log by reusing PC's log; PC still refuses it.
    let _ = &mut fake_log;
    let (acc, dial) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            nx::accept(&ep_pc, conn, &pc_log).await.map(|_| ())
        },
        async {
            nx::dial(&ep_x, &fake_log, &pc.id(), &net::dial_info(&ep_pc), [0; 16])
                .await
                .map(|_| ())
        }
    );
    assert_eq!(acc.unwrap_err(), net::NetError::Identity);
    assert!(dial.is_err());

    for ep in [ep_pc, ep_phone, ep_x] {
        ep.close().await;
    }
}

/// Runs one pairing between `display` and `scanner` devices; returns both results.
async fn pair_once(
    disp: &Device,
    scan: &Device,
) -> (
    Result<net::pair::Paired, net::NetError>,
    Result<net::pair::Paired, net::NetError>,
) {
    pair_once_confirm(disp, scan, true, true).await
}

async fn pair_once_confirm(
    disp: &Device,
    scan: &Device,
    display_accepts: bool,
    scanner_accepts: bool,
) -> (
    Result<net::pair::Paired, net::NetError>,
    Result<net::pair::Paired, net::NetError>,
) {
    let ep_d = net::bind(&disp.keys.ik, Relay::Disabled).await.unwrap();
    let ep_s = net::bind(&scan.keys.ik, Relay::Disabled).await.unwrap();
    let mut window = Window::open(
        disp.id(),
        net::dial_info(&ep_d),
        disp.name.clone(),
        disp.group_id(),
        now_ms() / 1000,
    )
    .unwrap();
    let qr = QrPayload::parse(&window.qr_text()).unwrap();
    let r = tokio::join!(
        async {
            let conn = accept_conn(&ep_d).await;
            net::pair::display(
                &ep_d,
                conn,
                &mut window,
                disp,
                now_ms(),
                |_| async { display_accepts },
                |_| async { Ok(()) },
            )
            .await
        },
        net::pair::scan(
            &ep_s,
            &qr,
            scan,
            now_ms(),
            |_| async { scanner_accepts },
            |_| async { Ok(()) }
        )
    );
    ep_d.close().await;
    ep_s.close().await;
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_resolution_table_all_rows() {
    // Row 1: none/none → new group (display appends genesis + add).
    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &phone).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(d.log.records().len(), 2);
    assert_eq!(d.log.head(), s.log.head());
    pc.log = Some(d.log);
    phone.log = Some(s.log);
    let g = pc.group_id().unwrap();

    // Row 2: display in G, scanner none → display adds the scanner.
    let mut tablet = Device::new("tablet", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &tablet).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(d.log.group_id(), g);
    assert_eq!(d.log.records().len(), 3);
    assert!(s.log.is_member(&tablet.id()));
    pc.log = Some(d.log);
    tablet.log = Some(s.log);

    // Row 3: display none, scanner in G → the scanner appends add(display).
    let mut laptop = Device::new("laptop", platform::WINDOWS).unwrap();
    let (d, s) = pair_once(&laptop, &tablet).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(s.log.group_id(), g);
    assert!(d.log.is_member(&laptop.id()) && d.log.is_member(&tablet.id()));
    assert_eq!(d.log.records().len(), 4);
    laptop.log = Some(d.log);

    // Row 4: both in G (same head) → already paired, no new records.
    let (d, s) = pair_once(&laptop, &tablet).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(d.log.records().len(), 4);
    assert_eq!(s.log.head(), laptop.head());

    // Row 5: different groups → PAIR_OTHER_GROUP, nothing changes.
    let other_pc = Device::new("other-pc", platform::WINDOWS).unwrap();
    let mut other_phone = Device::new("other-phone", platform::ANDROID).unwrap();
    let (_, s) = pair_once(&other_pc, &other_phone).await;
    other_phone.log = Some(s.unwrap().log);
    let (d, s) = pair_once(&pc, &other_phone).await;
    assert_eq!(
        d.unwrap_err(),
        net::NetError::Closed(warpshot_core::xfer::code::PAIR_OTHER_GROUP)
    );
    assert!(s.is_err());
    let _ = phone;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_readmits_removed_phone_with_stale_log() {
    use warpshot_core::log::{Op, RecordBody, RemoveReason, sign_record};
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/test-vectors/pair-recovery.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
        let mut phone = Device::new("phone", platform::ANDROID).unwrap();
        let (d, s) = pair_once(&pc, &phone).await;
        pc.log = Some(d.unwrap().log);
        phone.log = Some(s.unwrap().log);
        let log = pc.log.as_mut().unwrap();
        let (seq, prev) = log.next_position();
        let reason = match case["reason"].as_u64().unwrap() {
            0 => RemoveReason::User,
            1 => RemoveReason::LostOrStolen,
            3 => RemoveReason::NotMe,
            _ => panic!("unknown recovery vector"),
        };
        let body = RecordBody {
            group_id: log.group_id(),
            seq,
            prev,
            created_at: now_ms(),
            subject: phone.id(),
            op: Op::Remove(reason),
        };
        log.append(&sign_record(&pc.keys.ik, &body), now_ms())
            .unwrap();
        assert!(!log.is_member(&phone.id()));
        // A photographed QR or a refused confirmation must never undo revocation.
        for (display_accepts, scanner_accepts) in [(false, true), (true, false)] {
            let (d, s) = pair_once_confirm(&pc, &phone, display_accepts, scanner_accepts).await;
            assert!(d.is_err() && s.is_err());
            assert!(!pc.log.as_ref().unwrap().is_member(&phone.id()));
        }
        if case["expect"] == "revoked" {
            // Refused before the SAS; only a new identity (a reset phone) gets in.
            let revoked = net::NetError::Closed(warpshot_core::xfer::code::PAIR_REVOKED);
            let (d, s) = pair_once(&pc, &phone).await;
            assert_eq!(d.unwrap_err(), revoked);
            assert_eq!(s.unwrap_err(), revoked);
            let fresh = Device::new("phone", platform::ANDROID).unwrap();
            let (d, s) = pair_once(&pc, &fresh).await;
            let (d, s) = (d.unwrap(), s.unwrap());
            assert_eq!(d.log.records().len(), 4);
            assert_eq!(d.log.head(), s.log.head());
            assert!(s.log.is_member(&fresh.id()) && !s.log.is_member(&phone.id()));
            assert!(s.log.is_revoked(&phone.id()));
            continue;
        }
        assert_eq!(case["expect"], "readmit");
        let (d, s) = pair_once(&pc, &phone).await;
        let d = d.unwrap();
        let s = s.unwrap();
        assert_eq!(d.log.records().len(), 4);
        assert_eq!(d.log.head(), s.log.head());
        assert!(s.log.is_member(&phone.id()) && s.log.is_member(&pc.id()));
        assert!(matches!(
            s.log.records().last().unwrap().body.op,
            Op::Add(_)
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_driven_transfer() {
    use warpshot_core::net::flow::{self, PendingSessions, WakeAction};
    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &phone).await;
    pc.log = Some(d.unwrap().log);
    phone.log = Some(s.unwrap().log);
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();

    // PC (sender) keeps the items pending and seals a connect wake for the phone.
    let mut pending = PendingSessions::default();
    let items = vec![nx::text_item(1, "pano içeriği", now_ms()).unwrap()];
    let session = pending.insert(phone.id(), items.clone()).unwrap();
    let env = flow::connect_wake(&ep_pc, &pc, &phone.id(), session, &items, now_ms()).unwrap();
    assert!(warpshot_core::b64u::encode(&env).len() <= warpshot_core::wake::MAX_ENVELOPE_B64U);

    // Phone opens it (the server/FCM only relayed opaque bytes).
    let mut replay = warpshot_core::wake::ReplayCache::default();
    let (sender, action) = flow::open_wake(&phone, &env, now_ms(), &mut replay).unwrap();
    assert_eq!(sender, pc.id());
    let WakeAction::Connect {
        session: got_session,
        dial,
        preview,
        ..
    } = action
    else {
        panic!("connect expected")
    };
    assert_eq!(got_session, session);
    assert_eq!(preview.unwrap().count, 1);
    // Replaying the same envelope is refused.
    assert!(flow::open_wake(&phone, &env, now_ms(), &mut replay).is_err());

    let pc_log = pc.log.clone().unwrap();
    let phone_log = phone.log.clone().unwrap();
    let dir = tmpdir("wake");
    let policy = Policy {
        dir,
        max_size: 1 << 30,
        accept_large: false,
    };
    let (sent, received) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            let s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
            let p = pending
                .take(&s.hello_session, &s.peer)
                .expect("pending session");
            s.send_items(p.items).await
        },
        async {
            let s = flow::answer_connect(
                &ep_phone,
                &phone_log,
                &sender,
                got_session,
                &dial,
                |_, _, _| {},
            )
            .await
            .unwrap();
            s.receive(&policy, |_| true).await
        }
    );
    assert_eq!(sent.unwrap(), vec![(1, true)]);
    assert_eq!(
        received.unwrap()[0].item.text.as_deref(),
        Some("pano içeriği")
    );
    assert!(pending.is_empty());
    ep_pc.close().await;
    ep_phone.close().await;
}

/// Waits until `dir` holds a `.part` file (a stream is mid-flight). Sizes in
/// a Windows directory listing lag behind open files, so only the name counts.
async fn part_appears(dir: &std::path::Path) {
    let wait = async {
        loop {
            let busy = std::fs::read_dir(dir)
                .unwrap()
                .any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".part"));
            if busy {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(20), wait)
        .await
        .expect("no .part file appeared");
}

fn dir_is_empty(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_none()
}

fn big_item(id: u32, len: usize) -> OutItem {
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    OutItem {
        item: Item {
            id,
            kind: kind::FILE,
            name: "video.mp4".into(),
            mime: "video/mp4".into(),
            size: len as u64,
            created_at: 0,
            text: None,
        },
        source: Source::Bytes(data),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progress_and_cancel() {
    use std::sync::{Arc, Mutex};
    use warpshot_core::net::xfer::{Cancel, Progress};

    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &phone).await;
    pc.log = Some(d.unwrap().log);
    phone.log = Some(s.unwrap().log);
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let pc_log = pc.log.clone().unwrap();
    let phone_log = phone.log.clone().unwrap();
    let pc_addr = net::dial_info(&ep_pc);

    // One phone → PC transfer; each side may get a progress sink and a cancel handle.
    let run = |items: Vec<OutItem>,
               dir: PathBuf,
               send_obs: Option<(Arc<Mutex<Vec<Progress>>>, Cancel)>,
               recv_obs: Option<(Arc<Mutex<Vec<Progress>>>, Cancel)>| {
        let (ep_pc, ep_phone, pc_log, phone_log, pc_addr, pc_id) = (
            ep_pc.clone(),
            ep_phone.clone(),
            pc_log.clone(),
            phone_log.clone(),
            pc_addr.clone(),
            pc.id(),
        );
        async move {
            let policy = Policy {
                dir,
                max_size: 1 << 30,
                accept_large: false,
            };
            tokio::join!(
                async {
                    let conn = accept_conn(&ep_pc).await;
                    let mut s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
                    if let Some((log, c)) = recv_obs {
                        s.on_progress(move |p| log.lock().unwrap().push(p));
                        s.cancel_with(&c);
                    }
                    s.receive(&policy, |_| true).await
                },
                async {
                    let mut s = nx::dial(&ep_phone, &phone_log, &pc_id, &pc_addr, [0; 16])
                        .await
                        .unwrap();
                    if let Some((log, c)) = send_obs {
                        s.on_progress(move |p| log.lock().unwrap().push(p));
                        s.cancel_with(&c);
                    }
                    s.send_items(items).await
                }
            )
        }
    };

    // --- 1. A complete transfer reports 0 → total on both sides, monotonic.
    let dir = tmpdir("progress");
    let (tx, rx) = (Arc::default(), Arc::default());
    let items = vec![
        nx::text_item(1, "kısa not", now_ms()).unwrap(),
        big_item(2, 3 << 20),
        big_item(3, 100_000),
    ];
    let total = (3u64 << 20) + 100_000;
    let (r, s) = run(
        items,
        dir.clone(),
        Some((Arc::clone(&tx), Cancel::new())),
        Some((Arc::clone(&rx), Cancel::new())),
    )
    .await;
    assert_eq!(s.unwrap(), vec![(1, true), (2, true), (3, true)]);
    assert_eq!(r.unwrap().len(), 3);
    for log in [tx, rx] {
        let log: Vec<Progress> = log.lock().unwrap().clone();
        let first = log.first().unwrap();
        let last = log.last().unwrap();
        assert_eq!((first.done, first.total), (0, total));
        assert_eq!((last.done, last.total), (total, total));
        assert!(log.windows(2).all(|w| w[0].done <= w[1].done));
    }

    // --- 2. The receiver cancels mid-stream: both sides end `Cancelled`, the
    // partial file is deleted and nothing is saved.
    let dir = tmpdir("cancel-recv");
    let cancel = Cancel::new();
    let watcher = {
        let (dir, cancel) = (dir.clone(), cancel.clone());
        async move {
            part_appears(&dir).await;
            cancel.cancel();
        }
    };
    let ((r, s), ()) = tokio::join!(
        run(
            vec![big_item(1, 64 << 20)],
            dir.clone(),
            None,
            Some((Arc::default(), cancel)),
        ),
        watcher
    );
    assert_eq!(r.unwrap_err(), net::NetError::Cancelled);
    assert_eq!(s.unwrap_err(), net::NetError::Cancelled);
    assert!(dir_is_empty(&dir), "no partial or final file");

    // --- 3. The sender cancels mid-stream: same outcome.
    let dir = tmpdir("cancel-send");
    let cancel = Cancel::new();
    let watcher = {
        let (dir, cancel) = (dir.clone(), cancel.clone());
        async move {
            part_appears(&dir).await;
            cancel.cancel();
        }
    };
    let ((r, s), ()) = tokio::join!(
        run(
            vec![big_item(1, 64 << 20)],
            dir.clone(),
            Some((Arc::default(), cancel)),
            None,
        ),
        watcher
    );
    assert_eq!(s.unwrap_err(), net::NetError::Cancelled);
    assert_eq!(r.unwrap_err(), net::NetError::Cancelled);
    assert!(dir_is_empty(&dir), "no partial or final file");

    // --- 4. A handle cancelled before the session exists: `cancelled()`
    // resolves, and attaching it closes the connection at once.
    let cancel = Cancel::new();
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), cancel.cancelled())
        .await
        .unwrap();
    let dir = tmpdir("cancel-early");
    let (r, s) = run(
        vec![big_item(1, 1000)],
        dir.clone(),
        Some((Arc::default(), cancel)),
        None,
    )
    .await;
    assert_eq!(s.unwrap_err(), net::NetError::Cancelled);
    assert!(r.is_err());
    assert!(dir_is_empty(&dir));

    // --- 5. Cancel after the first of two files is saved: the saved file
    // stays and is reported by `receive_keep`; the second leaves nothing.
    let dir = tmpdir("cancel-keep");
    let cancel = Cancel::new();
    let mut first = big_item(1, 50_000);
    first.item.name = "first.bin".into();
    let items = vec![first, big_item(2, 64 << 20)];
    let watcher = {
        let (dir, cancel) = (dir.clone(), cancel.clone());
        async move {
            // The first file is final and the second is streaming.
            let wait = async {
                loop {
                    let names: Vec<String> = std::fs::read_dir(&dir)
                        .unwrap()
                        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect();
                    if names.iter().any(|n| n == "first.bin")
                        && names.iter().any(|n| n.ends_with(".part"))
                    {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(20), wait)
                .await
                .expect("second stream never started");
            cancel.cancel();
        }
    };
    let policy = Policy {
        dir: dir.clone(),
        max_size: 1 << 30,
        accept_large: false,
    };
    let ((kept, r), s, ()) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            let mut s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
            s.cancel_with(&cancel);
            s.receive_keep(&policy, |_| true).await
        },
        async {
            nx::dial(&ep_phone, &phone_log, &pc.id(), &pc_addr, [0; 16])
                .await
                .unwrap()
                .send_items(items)
                .await
        },
        watcher
    );
    assert_eq!(r.unwrap_err(), net::NetError::Cancelled);
    assert_eq!(s.unwrap_err(), net::NetError::Cancelled);
    assert_eq!(kept.len(), 1, "the saved file is reported");
    assert_eq!(kept[0].item.name, "first.bin");
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["first.bin".to_string()], "only the saved file");

    ep_pc.close().await;
    ep_phone.close().await;
}

/// How the receiver's user answers the question about large items (§8.4).
#[derive(Clone, Copy)]
enum Answer {
    Yes,
    No,
    /// No way to ask (no UI): the core declines with "too large".
    CantAsk,
    /// The question stays open until it is withdrawn.
    Never,
    /// "Yes", but only after this long.
    YesAfter(std::time::Duration),
}

#[derive(Clone, Copy, PartialEq)]
enum CancelBy {
    Nobody,
    Sender,
    Receiver,
}

struct AskRun {
    kept: Vec<nx::Received>,
    recv: Result<(), net::NetError>,
    sent: Result<Vec<(u32, bool)>, net::NetError>,
    /// What the question showed; empty if none was asked.
    asked: Vec<Item>,
    /// The question was dropped without an answer.
    withdrawn: bool,
}

/// Sets its flag when dropped: the core withdrew a question.
struct Withdrawn(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for Withdrawn {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One phone → PC transfer where the PC asks about items above 10 bytes.
async fn ask_run(
    pc: &Device,
    phone: &Device,
    items: Vec<OutItem>,
    answer: Answer,
    cancel_by: CancelBy,
) -> AskRun {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use warpshot_core::net::xfer::Cancel;

    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let (pc_log, phone_log) = (pc.log.clone().unwrap(), phone.log.clone().unwrap());
    let pc_addr = net::dial_info(&ep_pc);
    let policy = Policy {
        dir: tmpdir("ask"),
        max_size: 10,
        accept_large: false,
    };
    let asked = Arc::new(Mutex::new(Vec::new()));
    let withdrawn = Arc::new(AtomicBool::new(false));
    let (send_cancel, recv_cancel) = (Cancel::new(), Cancel::new());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let ask = {
        let (asked, withdrawn) = (Arc::clone(&asked), Arc::clone(&withdrawn));
        move |large: Vec<Item>| async move {
            *asked.lock().unwrap() = large;
            let _ = started_tx.send(());
            match answer {
                Answer::Yes => Some(true),
                Answer::No => Some(false),
                Answer::CantAsk => None,
                Answer::Never => {
                    let _guard = Withdrawn(withdrawn);
                    std::future::pending::<Option<bool>>().await
                }
                Answer::YesAfter(d) => {
                    tokio::time::sleep(d).await;
                    Some(true)
                }
            }
        }
    };
    let canceller = {
        let c = match cancel_by {
            CancelBy::Sender => Some(send_cancel.clone()),
            CancelBy::Receiver => Some(recv_cancel.clone()),
            CancelBy::Nobody => None,
        };
        async move {
            if let Some(c) = c
                && started_rx.await.is_ok()
            {
                c.cancel();
            }
        }
    };
    let ((kept, recv), sent, ()) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            let mut s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
            s.cancel_with(&recv_cancel);
            s.receive_keep_asking(&policy, |_| true, ask).await
        },
        async {
            let mut s = nx::dial(&ep_phone, &phone_log, &pc.id(), &pc_addr, [0; 16])
                .await
                .unwrap();
            s.cancel_with(&send_cancel);
            s.send_items(items).await
        },
        canceller
    );
    ep_pc.close().await;
    ep_phone.close().await;
    let asked = std::mem::take(&mut *asked.lock().unwrap());
    AskRun {
        kept,
        recv,
        sent,
        asked,
        withdrawn: withdrawn.load(Ordering::SeqCst),
    }
}

async fn paired_pc_and_phone() -> (Device, Device) {
    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &phone).await;
    pc.log = Some(d.unwrap().log);
    phone.log = Some(s.unwrap().log);
    (pc, phone)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_items_ask_the_user() {
    use warpshot_core::xfer::decline;
    let (pc, phone) = paired_pc_and_phone().await;
    let small = || nx::text_item(1, "küçük", now_ms()).unwrap();

    // Small items only: no question.
    let r = ask_run(&pc, &phone, vec![small()], Answer::No, CancelBy::Nobody).await;
    assert!(r.asked.is_empty(), "nothing above the threshold");
    assert_eq!(r.sent.unwrap(), vec![(1, true)]);

    // "Yes": the large item arrives; the question named it.
    let r = ask_run(
        &pc,
        &phone,
        vec![big_item(2, 4000)],
        Answer::Yes,
        CancelBy::Nobody,
    )
    .await;
    assert_eq!(r.asked.len(), 1);
    assert_eq!((r.asked[0].id, r.asked[0].size), (2, 4000));
    assert_eq!(r.sent.unwrap(), vec![(2, true)]);
    r.recv.unwrap();
    assert_eq!(r.kept.len(), 1);

    // "No" to a mixed offer: only the small item is accepted.
    let r = ask_run(
        &pc,
        &phone,
        vec![small(), big_item(2, 4000)],
        Answer::No,
        CancelBy::Nobody,
    )
    .await;
    assert_eq!(r.asked.len(), 1, "only the large item is asked about");
    assert_eq!(r.sent.unwrap(), vec![(1, true), (2, false)]);
    assert_eq!(r.kept.len(), 1);
    assert!(r.kept[0].item.is_inline());

    // "No" with nothing else: declined by the user.
    let r = ask_run(
        &pc,
        &phone,
        vec![big_item(2, 4000)],
        Answer::No,
        CancelBy::Nobody,
    )
    .await;
    assert_eq!(r.sent.unwrap_err(), net::NetError::Declined(decline::USER));
    r.recv.unwrap();
    assert!(r.kept.is_empty());

    // No way to ask: declined as too large.
    let r = ask_run(
        &pc,
        &phone,
        vec![big_item(2, 4000)],
        Answer::CantAsk,
        CancelBy::Nobody,
    )
    .await;
    assert_eq!(
        r.sent.unwrap_err(),
        net::NetError::Declined(decline::TOO_LARGE)
    );

    // The sender cancels while the question is open: it is withdrawn.
    let r = ask_run(
        &pc,
        &phone,
        vec![big_item(2, 4000)],
        Answer::Never,
        CancelBy::Sender,
    )
    .await;
    assert_eq!(r.sent.unwrap_err(), net::NetError::Cancelled);
    assert_eq!(r.recv.unwrap_err(), net::NetError::Cancelled);
    assert!(r.withdrawn, "the question is withdrawn");

    // The receiver cancels while asking (e.g. Cancel in its notification).
    let r = ask_run(
        &pc,
        &phone,
        vec![big_item(2, 4000)],
        Answer::Never,
        CancelBy::Receiver,
    )
    .await;
    assert_eq!(r.recv.unwrap_err(), net::NetError::Cancelled);
    assert_eq!(r.sent.unwrap_err(), net::NetError::Cancelled);
    assert!(r.withdrawn);
}

/// The sender waits for an answer longer than the 30 s idle timeout (§8.4).
/// Takes ~35 s: `cargo test -p warpshot-core --test e2e -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow (35 s)"]
async fn a_slow_answer_is_still_accepted() {
    let (pc, phone) = paired_pc_and_phone().await;
    let r = ask_run(
        &pc,
        &phone,
        vec![big_item(2, 4000)],
        Answer::YesAfter(std::time::Duration::from_secs(35)),
        CancelBy::Nobody,
    )
    .await;
    assert_eq!(r.sent.unwrap(), vec![(2, true)]);
    assert_eq!(r.kept.len(), 1);
}

/// What the woken phone sees when it answers a wake with `session`: the dial,
/// the log sync and the receive (as the app runs them).
async fn answer_wake(
    ep_phone: &iroh::Endpoint,
    phone: &Device,
    pc: &Device,
    pc_addr: &warpshot_core::wake::DialInfo,
    session: [u8; 16],
) -> Result<Vec<nx::Received>, net::NetError> {
    let mut log = phone.log.clone().unwrap();
    let mut s =
        net::flow::answer_connect(ep_phone, &log, &pc.id(), session, pc_addr, |_, _, _| {}).await?;
    s.sync_logs(&mut log, now_ms()).await?;
    let policy = Policy {
        dir: tmpdir("disp"),
        max_size: 1 << 30,
        accept_large: false,
    };
    s.receive(&policy, |_| true).await
}

/// §7.4: a woken device whose dial fails on the network dials again with the
/// same session; the sender's answer (here `PROTOCOL` for a session it doesn't
/// know) ends the dial at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_dial_is_retried_but_not_a_refusal() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use warpshot_core::{net::dispatch::Dispatcher, xfer::code};

    let (pc, phone) = paired_pc_and_phone().await;
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let pc_log = pc.log.clone().unwrap();
    let phone_log = phone.log.clone().unwrap();
    let pc_addr = net::dial_info(&ep_pc);
    let pc_id = pc.id();
    let failures: Arc<Mutex<Vec<(u32, net::NetError)>>> = Arc::default();
    let record = |n: u32, e: &net::NetError, _ms: u64| {
        failures.lock().unwrap().push((n, e.clone()));
    };

    // The first attempt is refused at the QUIC level; the second one gets through.
    let session = [9u8; 16];
    let (dialed, accepted) = tokio::join!(
        net::flow::answer_connect(&ep_phone, &phone_log, &pc_id, session, &pc_addr, record),
        async {
            ep_pc.accept().await.unwrap().refuse();
            let conn = accept_conn(&ep_pc).await;
            nx::accept(&ep_pc, conn, &pc_log).await
        }
    );
    assert_eq!(dialed.unwrap().hello_session, session);
    assert_eq!(accepted.unwrap().hello_session, session);
    {
        let f = failures.lock().unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].0, 1);
        assert!(net::flow::dial_retryable(&f[0].1), "{:?}", f[0].1);
    }

    // A session the sender doesn't know: one attempt, no pause, `PROTOCOL`.
    failures.lock().unwrap().clear();
    let notes: Arc<Mutex<Vec<String>>> = Arc::default();
    let disp = Dispatcher::with_hook(Box::new({
        let notes = Arc::clone(&notes);
        move |why| notes.lock().unwrap().push(why)
    }));
    let _w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let t0 = Instant::now();
    let r =
        net::flow::answer_connect(&ep_phone, &phone_log, &pc_id, [7; 16], &pc_addr, record).await;
    assert!(
        matches!(r, Err(net::NetError::Closed(code::PROTOCOL))),
        "{:?}",
        r.err()
    );
    assert_eq!(failures.lock().unwrap().len(), 1);
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    // The sender's diagnostics hook says why (it runs right after the close).
    for _ in 0..50 {
        if !notes.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*notes.lock().unwrap(), vec!["unknown session".to_owned()]);

    ep_pc.close().await;
    ep_phone.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_routes_and_answers_cancelled_sessions() {
    use std::time::Duration;
    use tokio::time::Instant;
    use warpshot_core::net::dispatch::Dispatcher;

    let (pc, phone) = paired_pc_and_phone().await;
    let (pc, phone) = (std::sync::Arc::new(pc), std::sync::Arc::new(phone));
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    let pc_log = pc.log.clone().unwrap();
    let pc_addr = net::dial_info(&ep_pc);
    let disp = Dispatcher::new();
    let is_cancelled =
        |r: &Result<Vec<nx::Received>, net::NetError>| matches!(r, Err(net::NetError::Cancelled));

    // A waiting send gets the connection that presents its session.
    let mut w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let session = w.session();
    let (got, sent) = tokio::join!(
        answer_wake(&ep_phone, &phone, &pc, &pc_addr, session),
        async {
            let mut s = w.arrived().await.unwrap();
            s.sync_logs(&mut pc_log.clone(), now_ms()).await.unwrap();
            s.send_items(vec![nx::text_item(1, "merhaba", now_ms()).unwrap()])
                .await
        }
    );
    assert_eq!(sent.unwrap(), vec![(1, true)]);
    assert_eq!(got.unwrap()[0].item.text.as_deref(), Some("merhaba"));

    // Cancelled while waiting: a late dial ends as a cancel on the phone.
    let w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let session = w.session();
    w.cancel(Instant::now() + Duration::from_secs(10), ());
    let r = answer_wake(&ep_phone, &phone, &pc, &pc_addr, session).await;
    assert!(is_cancelled(&r), "late dial after a cancel: {r:?}");

    // Cancelled after the dial arrived but before the send took it.
    let w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let session = w.session();
    let late = tokio::spawn({
        let (ep_phone, phone, pc, pc_addr) =
            (ep_phone.clone(), phone.clone(), pc.clone(), pc_addr.clone());
        async move { answer_wake(&ep_phone, &phone, &pc, &pc_addr, session).await }
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    w.cancel(Instant::now() + Duration::from_secs(10), ());
    let r = late.await.unwrap();
    assert!(is_cancelled(&r), "dial already arrived, then cancel: {r:?}");

    // An unknown session, a withdrawn one and an expired cancel are refused as protocol errors.
    let r = answer_wake(&ep_phone, &phone, &pc, &pc_addr, [7; 16]).await;
    assert!(r.is_err() && !is_cancelled(&r), "unknown session: {r:?}");
    let w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let session = w.session();
    drop(w);
    let r = answer_wake(&ep_phone, &phone, &pc, &pc_addr, session).await;
    assert!(r.is_err() && !is_cancelled(&r), "withdrawn session: {r:?}");
    let w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let session = w.session();
    w.cancel(Instant::now() + Duration::from_millis(200), ());
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = answer_wake(&ep_phone, &phone, &pc, &pc_addr, session).await;
    assert!(r.is_err() && !is_cancelled(&r), "cancel expired: {r:?}");

    // A pairing connection goes to the pairing window while a send waits, and
    // the send still gets its own connection afterwards.
    let mut w = disp.expect(&ep_pc, phone.id(), &pc_log).unwrap();
    let pairing = disp.expect_pairing(&ep_pc);
    let conn = net::connect(&ep_phone, &pc.id(), &pc_addr, warpshot_core::pair::ALPN)
        .await
        .unwrap();
    let got_pair = tokio::time::timeout(Duration::from_secs(10), pairing)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got_pair.alpn(), warpshot_core::pair::ALPN);
    conn.close(0u32.into(), b"");
    let session = w.session();
    let (got, sent) = tokio::join!(
        answer_wake(&ep_phone, &phone, &pc, &pc_addr, session),
        async {
            let mut s = w.arrived().await.unwrap();
            s.sync_logs(&mut pc_log.clone(), now_ms()).await.unwrap();
            s.send_items(vec![nx::text_item(1, "ikinci", now_ms()).unwrap()])
                .await
        }
    );
    assert_eq!(sent.unwrap(), vec![(1, true)]);
    assert_eq!(got.unwrap()[0].item.text.as_deref(), Some("ikinci"));

    ep_pc.close().await;
    ep_phone.close().await;
}
