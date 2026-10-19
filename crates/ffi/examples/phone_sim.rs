//! Simulated phone for agent end-to-end tests: drives the same `Warpshot`
//! object the Android app uses, with an INSECURE plaintext keystore.
//!
//! ```text
//! phone_sim <dir> <server_url> pair <qr_text>
//! phone_sim <dir> <server_url> send-text <target_hex> <text>
//! phone_sim <dir> <server_url> send-file <target_hex> <path>
//! phone_sim <dir> <server_url> send-file-cancel <target_hex> <path>   (cancels at the first progress report)
//! phone_sim <dir> <server_url> send-text-cancel <target_hex> <text>   (cancels 300 ms in)
//! phone_sim <dir> <server_url> send-text-cancel-stdin <target_hex> <text>   (cancels when a line
//!     arrives on stdin, then stays up 8 s like the app, so a late dial from the woken PC is answered)
//! phone_sim <dir> <server_url> devices
//! phone_sim <dir> <server_url> push-token <token>
//! phone_sim <dir> <server_url> wake <envelope_b64u> <inbox_dir>   (handles a push like PushService)
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::{Arc, OnceLock, Weak};

use warpshot_ffi::{
    OutgoingFile, PairConfirm, PlatformKeystore, TransferObserver, WarpError, Warpshot,
};

struct PlainKs;

impl PlatformKeystore for PlainKs {
    fn wrap(&self, _label: String, plain: Vec<u8>) -> Result<Vec<u8>, WarpError> {
        Ok(plain)
    }
    fn unwrap(&self, _label: String, wrapped: Vec<u8>) -> Result<Vec<u8>, WarpError> {
        Ok(wrapped)
    }
}

struct Yes;

impl PairConfirm for Yes {
    fn confirm(&self, sas: String, _peer_name: String, _peer_platform: u64) -> bool {
        println!("{{\"ev\":\"sas\",\"sas\":\"{sas}\"}}");
        true
    }
}

/// Prints progress as JSON lines; in cancel mode it cancels the transfer at
/// the first report (the session is up and data is about to flow).
struct Printer {
    cancel_on_progress: bool,
    w: OnceLock<Weak<Warpshot>>,
}

impl TransferObserver for Printer {
    fn on_progress(&self, transfer: u64, incoming: bool, done: u64, total: u64, _rate: u64) {
        println!(
            "{{\"ev\":\"progress\",\"transfer\":{transfer},\"in\":{incoming},\"done\":{done},\"total\":{total}}}"
        );
        if self.cancel_on_progress
            && let Some(w) = self.w.get().and_then(Weak::upgrade)
        {
            println!(
                "{{\"ev\":\"cancel\",\"found\":{}}}",
                w.cancel_transfer(transfer)
            );
        }
    }
    fn on_slow_route(&self, _incoming: bool) {}
    fn on_path(&self, _incoming: bool, _ms: u64, _note: String) {}
    fn on_route(&self, _incoming: bool, _direct: bool, _slow: bool, _ms: u64) {}
    fn on_diag(&self, note: String) {
        // stdout carries the JSON events.
        eprintln!("diag {note}");
    }
    fn on_ask_large(&self, _transfer: u64, _count: u32, _total: u64, _name: String) {}
    fn on_device_added(
        &self,
        _id: String,
        _name: String,
        _platform: u64,
        _by_id: String,
        _by_name: String,
    ) {
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        eprintln!("usage: phone_sim <dir> <server_url> <cmd> ...");
        std::process::exit(2);
    }
    let w = Warpshot::open(
        a[0].clone(),
        "Sim Phone".into(),
        a[1].clone(),
        Arc::new(PlainKs),
    )
    .expect("open");
    let printer = Arc::new(Printer {
        cancel_on_progress: a[2] == "send-file-cancel",
        w: OnceLock::new(),
    });
    let _ = printer.w.set(Arc::downgrade(&w));
    w.set_observer(Some(printer));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let w2 = Arc::clone(&w);
    let stay = a[2] == "send-text-cancel-stdin";
    let res: Result<String, WarpError> = rt.block_on(async move {
        match a[2].as_str() {
            "sync" => w2.sync().await.map(|()| "synced".into()),
            "remove" => w2
                .remove_device(a[3].clone(), false)
                .await
                .map(|()| "removed".into()),
            "pair" => w2.pair_scan(a[3].clone(), Arc::new(Yes)).await,
            "send-text" => w2
                .send_text(a[3].clone(), a[4].clone(), 1)
                .await
                .map(|()| "sent".into()),
            "send-file" => w2
                .send_files(a[3].clone(), vec![OutgoingFile { path: a[4].clone() }], 1)
                .await
                .map(|()| "sent".into()),
            "send-file-cancel" => w2
                .send_files(a[3].clone(), vec![OutgoingFile { path: a[4].clone() }], 7)
                .await
                .map(|()| "sent".into()),
            "send-text-cancel-stdin" => {
                let w3 = Arc::clone(&w2);
                std::thread::spawn(move || {
                    let mut line = String::new();
                    let _ = std::io::stdin().read_line(&mut line);
                    println!("{{\"found\":{}}}", w3.cancel_transfer(9));
                });
                w2.send_text(a[3].clone(), a[4].clone(), 9)
                    .await
                    .map(|()| "sent".into())
            }
            // Cancels 300 ms in, before the target could dial back.
            "send-text-cancel" => {
                let w3 = Arc::clone(&w2);
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    println!("{{\"found\":{}}}", w3.cancel_transfer(9));
                });
                w2.send_text(a[3].clone(), a[4].clone(), 9)
                    .await
                    .map(|()| "sent".into())
            }
            "push-token" => w2
                .register_push_token(a[3].clone())
                .await
                .map(|()| "registered".into()),
            "wake" => w2
                .handle_wake(a[3].clone(), a[4].clone(), 1, u64::MAX)
                .await
                .map(|items| format!("received {}", items.len())),
            "devices" => Ok(w2
                .devices()
                .await
                .iter()
                .map(|d| format!("{} {} me={}", d.id, d.name, d.me))
                .collect::<Vec<_>>()
                .join("\n")),
            _ => Ok("unknown command".into()),
        }
    });
    drop(rt);
    if stay {
        std::thread::sleep(std::time::Duration::from_secs(8));
    }
    match res {
        Ok(s) => println!("{s}"),
        Err(e) => {
            println!("error: {e:?}");
            drop(w);
            std::process::exit(1);
        }
    }
    drop(w);
}
