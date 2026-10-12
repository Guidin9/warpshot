//! Linux-specific network interfaces implementations.

use n0_error::{e, stack_error};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

use super::DefaultRouteDetails;
pub(super) use super::netdev_impl::{get_state, home_router};

#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("IO")]
    Io { source: std::io::Error },
    #[cfg(not(target_os = "android"))]
    #[error("no netlink response")]
    NoResponse {},
    #[cfg(not(target_os = "android"))]
    #[error("interface not found")]
    InterfaceNotFound {},
    #[error("iface field is missing")]
    MissingIfaceField {},
    #[error("destination field is missing")]
    MissingDestinationField {},
    #[error("mask field is missing")]
    MissingMaskField {},
    #[cfg(not(target_os = "android"))]
    #[error("netlink")]
    Netlink {
        source: netlink_proto::Error<netlink_packet_route::RouteNetlinkMessage>,
    },
    #[cfg(not(target_os = "android"))]
    #[error("unexpected netlink message")]
    UnexpectedNetlinkMessage {},
    #[cfg(not(target_os = "android"))]
    #[error("netlink error message: {message:?}")]
    NetlinkErrorMessage {
        message: netlink_packet_core::ErrorMessage,
    },
}

pub async fn default_route() -> Option<DefaultRouteDetails> {
    // /proc/net/route only contains IPv4 routes. If it finds one, return it.
    // If it returns Ok(None) (no IPv4 default route) or Err (file unreadable),
    // fall through to netlink which checks both IPv4 and IPv6.
    if let Ok(Some(route)) = default_route_proc().await {
        return Some(route);
    }

    #[cfg(target_os = "android")]
    let res = android::default_route().await;

    #[cfg(not(target_os = "android"))]
    let res = sane::default_route().await;

    res.ok().flatten()
}

const PROC_NET_ROUTE_PATH: &str = "/proc/net/route";

async fn default_route_proc() -> Result<Option<DefaultRouteDetails>, Error> {
    const ZERO_ADDR: &str = "00000000";
    let file = File::open(PROC_NET_ROUTE_PATH).await?;

    // Explicitly set capacity, this is min(4096, DEFAULT_BUF_SIZE):
    // https://github.com/google/gvisor/issues/5732
    // On a regular Linux kernel you can read the first 128 bytes of /proc/net/route,
    // then come back later to read the next 128 bytes and so on.
    //
    // In Google Cloud Run, where /proc/net/route comes from gVisor, you have to
    // read it all at once. If you read only the first few bytes then the second
    // read returns 0 bytes no matter how much originally appeared to be in the file.
    //
    // At the time of this writing (Mar 2021) Google Cloud Run has eth0 and eth1
    // with a 384 byte /proc/net/route. We allocate a large buffer to ensure we'll
    // read it all in one call.
    let reader = BufReader::with_capacity(8 * 1024, file);
    let mut lines_iter = reader.lines();
    while let Some(line) = lines_iter.next_line().await? {
        if !line.contains(ZERO_ADDR) {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let iface = fields.next().ok_or_else(|| e!(Error::MissingIfaceField))?;
        let destination = fields
            .next()
            .ok_or_else(|| e!(Error::MissingDestinationField))?;
        let mask = fields.nth(5).ok_or_else(|| e!(Error::MissingMaskField))?;
        // if iface.starts_with("tailscale") || iface.starts_with("wg") {
        //     continue;
        // }
        if destination == ZERO_ADDR && mask == ZERO_ADDR {
            return Ok(Some(DefaultRouteDetails {
                interface_name: iface.to_string(),
            }));
        }
    }
    Ok(None)
}

#[cfg(target_os = "android")]
mod android {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use jni::{
        jni_sig, jni_str,
        objects::{JObject, JString, JValue},
        refs::Reference as _,
    };

    use super::*;

    /// The default route's interface, from the active network's link properties
    /// (`ConnectivityManager.getLinkProperties(getActiveNetwork()).getInterfaceName()`)
    /// through JNI, via the context published to `ndk_context`.
    ///
    /// Warpshot patch: upstream runs `ip route show table 0` here. Forking the
    /// app process for that sometimes left the child stuck before `exec`, and
    /// the spawn then blocked a runtime thread for good, so the endpoint bind
    /// never returned (docs/spikes.md "Android bind hang").
    pub async fn default_route() -> Result<Option<DefaultRouteDetails>, Error> {
        let name = match catch_unwind(AssertUnwindSafe(interface_name_jni)) {
            Ok(Ok(name)) => name,
            Ok(Err(err)) => {
                tracing::debug!(%err, "default route via JNI failed");
                None
            }
            Err(_) => {
                tracing::debug!("ndk_context not initialized; no default route");
                None
            }
        };
        Ok(name.map(|interface_name| DefaultRouteDetails { interface_name }))
    }

    fn interface_name_jni() -> Result<Option<String>, jni::errors::Error> {
        let ctx = ndk_context::android_context();
        // SAFETY: `ndk_context` holds a valid JavaVM pointer for the process lifetime.
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
        vm.attach_current_thread(|env| {
            // SAFETY: the context is a global reference kept alive by `ndk_context`.
            let context = unsafe { JObject::from_raw(env, ctx.context().cast()) };
            let service = env.new_string("connectivity")?;
            let cm = env
                .call_method(
                    context,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&service)],
                )?
                .l()?;
            if cm.is_null() {
                return Ok(None);
            }
            let network = env
                .call_method(
                    &cm,
                    jni_str!("getActiveNetwork"),
                    jni_sig!("()Landroid/net/Network;"),
                    &[],
                )?
                .l()?;
            if network.is_null() {
                return Ok(None);
            }
            let props = env
                .call_method(
                    &cm,
                    jni_str!("getLinkProperties"),
                    jni_sig!("(Landroid/net/Network;)Landroid/net/LinkProperties;"),
                    &[JValue::Object(&network)],
                )?
                .l()?;
            if props.is_null() {
                return Ok(None);
            }
            let name = env
                .call_method(
                    &props,
                    jni_str!("getInterfaceName"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .l()?;
            if name.is_null() {
                return Ok(None);
            }
            let name = env.cast_local::<JString<'_>>(name)?;
            Ok(Some(name.try_to_string(env)?))
        })
    }
}

#[cfg(not(target_os = "android"))]
mod sane {
    use n0_error::e;
    use n0_future::{Either, StreamExt, TryStream};
    use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage};
    use netlink_packet_route::{
        AddressFamily, RouteNetlinkMessage,
        link::{LinkAttribute, LinkMessage},
        route::{RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType},
    };
    use netlink_sys::protocols::NETLINK_ROUTE;
    use tracing::{Instrument, info_span};

    use super::*;

    type Handle = netlink_proto::ConnectionHandle<RouteNetlinkMessage>;

    macro_rules! try_rtnl {
        ($msg: expr, $message_type:path) => {{
            use netlink_packet_core::NetlinkPayload;
            use netlink_packet_route::RouteNetlinkMessage;

            let (_header, payload) = $msg.into_parts();
            match payload {
                NetlinkPayload::InnerMessage($message_type(msg)) => msg,
                NetlinkPayload::Error(err) => {
                    return Err(e!(Error::NetlinkErrorMessage { message: err }));
                }
                _ => return Err(e!(Error::UnexpectedNetlinkMessage)),
            }
        }};
    }

    pub async fn default_route() -> Result<Option<DefaultRouteDetails>, Error> {
        let (connection, handle, _receiver) =
            netlink_proto::new_connection::<RouteNetlinkMessage>(NETLINK_ROUTE)?;

        let task = tokio::spawn(connection.instrument(info_span!("netlink.conn")));

        let default = default_route_netlink_family(&handle, AddressFamily::Inet).await?;
        let default = match default {
            Some(default) => Some(default),
            None => {
                default_route_netlink_family(&handle, netlink_packet_route::AddressFamily::Inet6)
                    .await?
            }
        };
        task.abort();
        task.await.ok();
        Ok(default.map(|(name, _index)| DefaultRouteDetails {
            interface_name: name,
        }))
    }

    fn get_route(
        handle: Handle,
        message: RouteMessage,
    ) -> impl TryStream<Ok = RouteMessage, Err = Error> {
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req, netlink_proto::sys::SocketAddr::new(0, 0)) {
            Ok(response) => Either::Left(
                response.map(move |msg| Ok(try_rtnl!(msg, RouteNetlinkMessage::NewRoute))),
            ),
            Err(e) => Either::Right(n0_future::stream::once::<Result<RouteMessage, Error>>(Err(
                e!(Error::Netlink, e),
            ))),
        }
    }

    fn create_route_message(family: netlink_packet_route::AddressFamily) -> RouteMessage {
        let mut message = RouteMessage::default();
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;
        message.header.address_family = family;
        message
    }

    /// Returns the `(name, index)` of the interface for the default route.
    async fn default_route_netlink_family(
        handle: &Handle,
        family: netlink_packet_route::AddressFamily,
    ) -> Result<Option<(String, u32)>, Error> {
        let msg = create_route_message(family);
        let mut routes = get_route(handle.clone(), msg);

        while let Some(route) = routes.try_next().await? {
            let route_attrs = route.attributes;

            if !route_attrs
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Gateway(_)))
            {
                // A default route has a gateway.
                continue;
            }

            if route.header.destination_prefix_length > 0 {
                // A default route has no destination prefix length because it needs to route all
                // destinations.
                continue;
            }

            let index = route_attrs.iter().find_map(|attr| match attr {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            });

            if let Some(index) = index {
                if index == 0 {
                    continue;
                }
                let name = iface_by_index(handle, index).await?;
                return Ok(Some((name, index)));
            }
        }
        Ok(None)
    }

    fn get_link(
        handle: Handle,
        message: LinkMessage,
    ) -> impl TryStream<Ok = LinkMessage, Err = Error> {
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetLink(message));
        req.header.flags = NLM_F_REQUEST;

        match handle.request(req, netlink_proto::sys::SocketAddr::new(0, 0)) {
            Ok(response) => Either::Left(
                response.map(move |msg| Ok(try_rtnl!(msg, RouteNetlinkMessage::NewLink))),
            ),
            Err(e) => Either::Right(n0_future::stream::once::<Result<LinkMessage, Error>>(Err(
                e!(Error::Netlink, e),
            ))),
        }
    }

    fn create_link_get_message(index: u32) -> LinkMessage {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message
    }

    async fn iface_by_index(handle: &Handle, index: u32) -> Result<String, Error> {
        let message = create_link_get_message(index);
        let mut links = get_link(handle.clone(), message);
        let msg = links
            .try_next()
            .await?
            .ok_or_else(|| e!(Error::NoResponse))?;

        for nla in msg.attributes {
            if let LinkAttribute::IfName(name) = nla {
                return Ok(name);
            }
        }
        Err(e!(Error::InterfaceNotFound))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn test_default_route_netlink() {
            let route = default_route().await.unwrap();
            // assert!(route.is_some());
            if let Some(route) = route {
                assert!(!route.interface_name.is_empty());
            }
        }
    }
}

/// Parses the output of the android `/system/bin/ip` command for the default route.
///
/// Searches for line like `default via 10.0.2.2. dev radio0 table 1016 proto static mtu
/// 1500`
#[cfg(any(target_os = "android", test))]
fn parse_android_ip_route(stdout: &str) -> Option<&str> {
    for line in stdout.lines() {
        if !line.starts_with("default via") {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        if let Some(_dev) = fields.find(|s: &&str| *s == "dev") {
            return fields.next();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_route_proc() {
        let route = default_route_proc().await.unwrap();
        // assert!(route.is_some());
        if let Some(route) = route {
            assert!(!route.interface_name.is_empty());
        }
    }

    #[test]
    fn test_parse_android_ip_route() {
        let stdout = "default via 10.0.2.2. dev radio0 table 1016 proto static mtu 1500";
        let iface = parse_android_ip_route(stdout).unwrap();
        assert_eq!(iface, "radio0");
    }
}
