use crate::error::ClientError;
use slipstream_core::net::{bind_first_resolved, bind_tcp_listener_addr, bind_udp_socket_addr};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};

pub(crate) fn compute_mtu(domain_len: usize) -> Result<u32, ClientError> {
    if domain_len >= 240 {
        return Err(ClientError::new(
            "Domain name is too long for DNS transport",
        ));
    }
    // Upstream payload is now carried in a NULL additional record and
    // is capped at 1000 bytes (MAX_UPSTREAM_PAYLOAD_LEN), matching the
    // downstream response limit.
    Ok(1000)
}

pub(crate) async fn bind_udp_socket() -> Result<TokioUdpSocket, ClientError> {
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    bind_udp_socket_addr(bind_addr, "UDP socket").map_err(map_io)
}

pub(crate) async fn bind_tcp_listener(
    host: &str,
    port: u16,
) -> Result<TokioTcpListener, ClientError> {
    bind_first_resolved(host, port, bind_tcp_listener_addr, "TCP listener")
        .await
        .map_err(map_io)
}

pub(crate) fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
