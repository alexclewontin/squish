use std::future::poll_fn;
use std::net::IpAddr;

use quinn::Endpoint;
use tokio::task::JoinHandle;

/// Spawn a background task that monitors network interface changes
/// and triggers QUIC connection migration when the local IP changes.
pub fn spawn_monitor(endpoint: Endpoint) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = monitor_loop(endpoint).await {
            tracing::warn!("migration monitor exited: {e}");
        }
    })
}

/// Returns `true` if the address is a loopback address (127.0.0.1 or ::1).
fn is_loopback(addr: IpAddr) -> bool {
    addr.is_loopback()
}

/// Returns `true` if the address is an IPv6 link-local address (fe80::/10).
fn is_ipv6_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

/// Returns `true` if this address should be skipped for migration.
///
/// Filters out:
/// - Loopback addresses (127.0.0.1, ::1)
/// - IPv6 link-local (fe80::) unless the endpoint is already bound to IPv6
fn should_skip(addr: IpAddr, endpoint_is_ipv6: bool) -> bool {
    if is_loopback(addr) {
        return true;
    }
    if is_ipv6_link_local(addr) && !endpoint_is_ipv6 {
        return true;
    }
    false
}

async fn monitor_loop(endpoint: Endpoint) -> anyhow::Result<()> {
    let mut watcher = if_watch::tokio::IfWatcher::new()?;

    loop {
        let event = poll_fn(|cx| watcher.poll_if_event(cx)).await;

        match event {
            Ok(if_watch::IfEvent::Up(net)) => {
                let addr = net.addr();

                let endpoint_is_ipv6 = endpoint.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);

                if should_skip(addr, endpoint_is_ipv6) {
                    tracing::debug!(%net, "ignoring interface (loopback or link-local)");
                    continue;
                }

                tracing::info!(%net, "new interface detected, migrating");

                match std::net::UdpSocket::bind((addr, 0u16)) {
                    Ok(socket) => match endpoint.rebind(socket) {
                        Ok(()) => {
                            tracing::info!(%net, "connection migrated");
                        }
                        Err(e) => {
                            tracing::warn!(%net, "rebind failed: {e}");
                        }
                    },
                    Err(e) => {
                        tracing::warn!(%net, "failed to bind socket: {e}");
                    }
                }
            }
            Ok(if_watch::IfEvent::Down(net)) => {
                tracing::info!(%net, "interface went down");
                // Don't act — quinn will detect the path failure on its own.
            }
            Err(e) => {
                tracing::warn!("if-watch error: {e}");
            }
        }
    }
}
