#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::types::Principal;

#[cfg(unix)]
#[must_use]
pub fn principal_from_peer_credentials(_stream: &UnixStream) -> Principal {
    unimplemented!("peer credential extraction lands in Pass 3")
}
