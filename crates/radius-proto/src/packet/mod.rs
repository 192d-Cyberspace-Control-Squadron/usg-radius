mod code;
#[allow(clippy::module_inception)]
mod packet;

pub use code::Code;
pub use packet::{Packet, PacketError};
