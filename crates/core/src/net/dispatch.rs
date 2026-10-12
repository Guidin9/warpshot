//! One accept loop per endpoint (protocol §7.4, §9 "Pending sessions").
//!
//! Every incoming connection goes through here: a transfer connection is handed
//! to the send that waits for its session; a late dial for a send that was
//! cancelled while waiting is closed with `CANCELLED` right after the
//! handshake, so the woken device ends quietly instead of reporting a failure;
//! a pairing connection goes to the open pairing window. Separate accept loops
//! per send (and one for pairing) used to compete for the same endpoint and
//! close each other's connections.
//!
//! Event-driven: one task per open endpoint (it ends when the endpoint closes),
//! one short task per incoming connection, and one timer per cancelled session.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use iroh::{
    Endpoint,
    endpoint::{Connection, Incoming},
};
use tokio::{sync::oneshot, time::Instant};

use super::{HANDSHAKE_TIMEOUT, NetError, close, xfer as nx};
use crate::{
    keys::{self, EndpointId},
    log::Log,
    pair,
    xfer::{self, code},
};

type Waiter = (EndpointId, oneshot::Sender<nx::Session>);

#[derive(Default)]
struct State {
    /// The endpoint the accept loop runs on (at most one is open at a time).
    ep: Option<Endpoint>,
    /// Admission checks use the log the latest send registered with.
    log: Option<Log>,
    waiting: HashMap<[u8; 16], Waiter>,
    /// Sessions of sends cancelled while waiting, until they would have expired.
    cancelled: HashMap<[u8; 16], EndpointId>,
    pairing: Option<oneshot::Sender<Connection>>,
}

#[derive(Default)]
pub struct Dispatcher {
    state: Mutex<State>,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dispatcher")
    }
}

/// Where an admitted transfer connection goes.
enum Route {
    Waiter(oneshot::Sender<nx::Session>),
    Cancelled,
    Unknown,
}

impl Dispatcher {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock leaves plain maps behind; keep going.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A send to `target` will wait for it to dial in (§7.4). Returns a fresh
    /// session id (inside [`Expected`]) for the wake envelope.
    pub fn expect(
        self: &Arc<Self>,
        ep: &Endpoint,
        target: EndpointId,
        log: &Log,
    ) -> Result<Expected, NetError> {
        let (tx, rx) = oneshot::channel();
        let session = {
            let mut st = self.lock();
            let mut session = [0u8; 16];
            loop {
                keys::random(&mut session).map_err(|_| NetError::State("rng"))?;
                // All-zero means "no session" (§8.3).
                if session != [0; 16]
                    && !st.waiting.contains_key(&session)
                    && !st.cancelled.contains_key(&session)
                {
                    break;
                }
            }
            st.log = Some(log.clone());
            st.waiting.insert(session, (target, tx));
            session
        };
        self.run_on(ep);
        Ok(Expected {
            disp: Arc::clone(self),
            session,
            rx,
        })
    }

    /// The pairing window waits for the scanner to dial in; the next pairing
    /// connection is handed to the returned receiver.
    pub fn expect_pairing(self: &Arc<Self>, ep: &Endpoint) -> oneshot::Receiver<Connection> {
        let (tx, rx) = oneshot::channel();
        self.lock().pairing = Some(tx);
        self.run_on(ep);
        rx
    }

    /// Starts the accept loop on `ep` unless one runs on the open endpoint.
    fn run_on(self: &Arc<Self>, ep: &Endpoint) {
        {
            let mut st = self.lock();
            if st.ep.as_ref().is_some_and(|e| !e.is_closed()) {
                return;
            }
            st.ep = Some(ep.clone());
        }
        let (this, ep) = (Arc::clone(self), ep.clone());
        tokio::spawn(async move { this.accept_loop(ep).await });
    }

    async fn accept_loop(self: Arc<Self>, ep: Endpoint) {
        while let Some(inc) = ep.accept().await {
            let (this, ep) = (Arc::clone(&self), ep.clone());
            tokio::spawn(async move { this.route(&ep, inc).await });
        }
        // The endpoint closed: no dial can arrive for the sends still waiting.
        let mut st = self.lock();
        if st.ep.as_ref().is_some_and(Endpoint::is_closed) {
            st.ep = None;
            st.waiting.clear();
            st.pairing = None;
        }
    }

    async fn route(&self, ep: &Endpoint, inc: Incoming) {
        let Ok(accepting) = inc.accept() else { return };
        let Ok(Ok(conn)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await else {
            return;
        };
        if conn.alpn() == pair::ALPN {
            let tx = self.lock().pairing.take();
            let unclaimed = match tx {
                Some(tx) => tx.send(conn).err(),
                None => Some(conn),
            };
            if let Some(conn) = unclaimed {
                close(&conn, code::PROTOCOL);
            }
            return;
        }
        if conn.alpn() != xfer::ALPN {
            close(&conn, code::PROTOCOL);
            return;
        }
        let Some(log) = self.lock().log.clone() else {
            close(&conn, code::PROTOCOL);
            return;
        };
        // Admission and handshake; on failure `accept` has closed the connection.
        let Ok(s) = nx::accept(ep, conn, &log).await else {
            return;
        };
        let route = {
            let mut st = self.lock();
            let session = s.hello_session;
            if st.waiting.get(&session).is_some_and(|(t, _)| *t == s.peer) {
                st.waiting
                    .remove(&session)
                    .map_or(Route::Unknown, |(_, tx)| Route::Waiter(tx))
            } else if st.cancelled.get(&session) == Some(&s.peer) {
                Route::Cancelled
            } else {
                Route::Unknown
            }
        };
        match route {
            Route::Waiter(tx) => {
                // The send gave up in the meantime.
                if let Err(s) = tx.send(s) {
                    close(&s.conn, code::CANCELLED);
                }
            }
            Route::Cancelled => close(&s.conn, code::CANCELLED),
            Route::Unknown => close(&s.conn, code::PROTOCOL),
        }
    }
}

/// A send waiting for its target to dial in. Dropping it withdraws the session.
pub struct Expected {
    disp: Arc<Dispatcher>,
    session: [u8; 16],
    rx: oneshot::Receiver<nx::Session>,
}

impl std::fmt::Debug for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Expected")
    }
}

impl Expected {
    /// The session id for the wake envelope.
    pub fn session(&self) -> [u8; 16] {
        self.session
    }

    /// Resolves when the target dials in with this session (admitted, handshake
    /// done). Fails if the endpoint closed first.
    pub async fn arrived(&mut self) -> Result<nx::Session, NetError> {
        (&mut self.rx).await.map_err(|_| NetError::Bind)
    }

    /// The send was cancelled while waiting (§9 "Pending sessions"): until
    /// `until`, a late dial with this session is closed with `CANCELLED`, and
    /// `keep` (e.g. the endpoint lease) is held so the endpoint stays open to
    /// answer it. A connection that already arrived is closed the same way.
    pub fn cancel<K: Send + 'static>(mut self, until: Instant, keep: K) {
        let target = self.disp.lock().waiting.remove(&self.session).map(|w| w.0);
        if let Ok(s) = self.rx.try_recv() {
            close(&s.conn, code::CANCELLED);
        }
        let Some(target) = target else { return };
        let (disp, session) = (Arc::clone(&self.disp), self.session);
        disp.lock().cancelled.insert(session, target);
        tokio::spawn(async move {
            tokio::time::sleep_until(until).await;
            disp.lock().cancelled.remove(&session);
            drop(keep);
        });
    }
}

impl Drop for Expected {
    fn drop(&mut self) {
        self.disp.lock().waiting.remove(&self.session);
    }
}
