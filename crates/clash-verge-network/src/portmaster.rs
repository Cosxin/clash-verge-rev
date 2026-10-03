//! Portmaster wire compatibility, based on Safing's GPL-3.0 windows_kext protocol.
//! Source: 21a2b0647fe98bd67cd2738853c29f736eb888a7. No driver is opened or installed here.

use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_BANDWIDTH_ROWS: usize = 10_000;

#[derive(Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Connection {
    pub request_id: u64,
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub payload_layer: u8,
    pub payload_bytes: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConnectionEnd {
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local: Endpoint,
    pub remote: Endpoint,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BandwidthDelta {
    pub local: Endpoint,
    pub remote: Endpoint,
    pub transmitted: u64,
    pub received: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Connection(Connection),
    End(ConnectionEnd),
    Bandwidth { protocol: u8, deltas: Vec<BandwidthDelta> },
    Log { severity: u8, message: String },
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        if count > self.0.len() {
            return Err(invalid("Truncated Portmaster field"));
        }
        let (value, remaining) = self.0.split_at(count);
        self.0 = remaining;
        Ok(value)
    }

    fn number<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid("Invalid Portmaster integer"))
    }

    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.number::<1>()?[0])
    }
    fn short(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.number()?))
    }
    fn word(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.number()?))
    }
    fn long(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.number()?))
    }
    fn address(&mut self, v6: bool) -> io::Result<IpAddr> {
        Ok(if v6 {
            Ipv6Addr::from(self.number::<16>()?).into()
        } else {
            Ipv4Addr::from(self.number::<4>()?).into()
        })
    }
    fn endpoint(&mut self, v6: bool) -> io::Result<Endpoint> {
        Ok(Endpoint {
            address: self.address(v6)?,
            port: self.short()?,
        })
    }
    fn connection_endpoints(&mut self, v6: bool) -> io::Result<(Endpoint, Endpoint)> {
        let local = self.address(v6)?;
        let remote = self.address(v6)?;
        Ok((
            Endpoint {
                address: local,
                port: self.short()?,
            },
            Endpoint {
                address: remote,
                port: self.short()?,
            },
        ))
    }
}

pub fn decode_frame(kind: u8, bytes: &[u8]) -> io::Result<Event> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid("Portmaster frame exceeds byte limit"));
    }
    let mut fields = Fields(bytes);
    let event = match kind {
        0 => {
            let severity = fields.byte()?;
            let message = std::str::from_utf8(fields.take(fields.0.len())?)
                .map_err(|_| invalid("Invalid Portmaster log encoding"))?
                .to_owned();
            Event::Log { severity, message }
        }
        1 | 2 => {
            let request_id = fields.long()?;
            let process_id = fields.long()?;
            let direction = fields.byte()?;
            let protocol = fields.byte()?;
            let (local, remote) = fields.connection_endpoints(kind == 2)?;
            let payload_layer = fields.byte()?;
            let payload_bytes = fields.word()?;
            // Consume but never retain packet payloads in the connection-monitoring pipeline.
            fields.take(payload_bytes as usize)?;
            Event::Connection(Connection {
                request_id,
                process_id,
                direction,
                protocol,
                local,
                remote,
                payload_layer,
                payload_bytes,
            })
        }
        3 | 4 => {
            let process_id = fields.long()?;
            let direction = fields.byte()?;
            let protocol = fields.byte()?;
            let (local, remote) = fields.connection_endpoints(kind == 4)?;
            Event::End(ConnectionEnd {
                process_id,
                direction,
                protocol,
                local,
                remote,
            })
        }
        5 | 6 => {
            let protocol = fields.byte()?;
            let count = fields.word()? as usize;
            let v6 = kind == 6;
            let row_bytes = if v6 { 52 } else { 28 };
            if count > MAX_BANDWIDTH_ROWS || count.checked_mul(row_bytes) != Some(fields.0.len()) {
                return Err(invalid("Invalid Portmaster bandwidth count or length"));
            }
            let mut deltas = Vec::with_capacity(count);
            for _ in 0..count {
                deltas.push(BandwidthDelta {
                    local: fields.endpoint(v6)?,
                    remote: fields.endpoint(v6)?,
                    transmitted: fields.long()?,
                    received: fields.long()?,
                });
            }
            Event::Bandwidth { protocol, deltas }
        }
        _ => return Err(invalid("Unknown Portmaster frame type")),
    };
    if !fields.0.is_empty() {
        return Err(invalid("Trailing Portmaster frame bytes"));
    }
    Ok(event)
}

/// A reader error is a transport fault; the policy owner must resolve held flows,
/// not retry by treating malformed bytes as another trusted frame.
pub fn read_event(reader: &mut impl Read) -> io::Result<Option<Event>> {
    let mut kind = [0];
    loop {
        match reader.read(&mut kind) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let length = u32::from_le_bytes(size) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(invalid("Portmaster frame exceeds byte limit"));
    }
    if kind[0] > 6 {
        return Err(invalid("Unknown Portmaster frame type"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    decode_frame(kind[0], &bytes).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Block,
    Drop,
}

pub fn verdict_command(request_id: u64, verdict: Verdict) -> [u8; 10] {
    let mut bytes = [0; 10];
    bytes[0] = 1;
    bytes[1..9].copy_from_slice(&request_id.to_le_bytes());
    bytes[9] = match verdict {
        Verdict::Accept => 2,
        Verdict::Block => 4,
        Verdict::Drop => 6,
    };
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decodes_actual_donor_corpus_without_unbounded_payload_storage() -> io::Result<()> {
        let data = include_bytes!("../tests/portmaster/rust_info_test.bin");
        let mut corpus = Cursor::new(data.as_slice());
        assert!(matches!(read_event(&mut corpus), Err(error) if error.kind() == io::ErrorKind::InvalidData));
        let mut counts = [0; 7];
        while (corpus.position() as usize) < data.len() {
            let kind = data[corpus.position() as usize] as usize;
            let event = read_event(&mut corpus)?.ok_or_else(|| invalid("Unexpected corpus end"))?;
            counts[kind] += 1;
            match event {
                Event::Connection(connection) => {
                    assert_eq!(connection.request_id, 1);
                    assert_eq!(connection.process_id, 2);
                    assert_eq!(connection.local.port, 5);
                    assert_eq!(connection.remote.port, 6);
                    assert_eq!(connection.payload_bytes, 10);
                }
                Event::Bandwidth { deltas, .. } => {
                    assert_eq!(deltas.len(), 2);
                    assert_eq!(deltas[0].transmitted, 3);
                    assert_eq!(deltas[0].received, 4);
                }
                Event::Log { message, .. } => assert_eq!(message, "prefix: test log"),
                Event::End(end) => assert_eq!(end.process_id, 1),
            }
        }
        assert_eq!(counts.iter().sum::<usize>(), 1000);
        assert!(counts.iter().all(|count| *count > 0));
        Ok(())
    }

    #[test]
    fn rejects_truncated_oversized_unknown_and_inconsistent_frames() {
        for bytes in [
            vec![0],
            vec![9, 0, 0, 0, 0],
            vec![0, 255, 255, 255, 255],
            vec![1, 4, 0, 0, 0, 0],
            vec![5, 5, 0, 0, 0, 6, 255, 255, 255, 255],
        ] {
            assert!(read_event(&mut Cursor::new(bytes)).is_err());
        }
        assert!(decode_frame(3, &[0; 23]).is_err());
        assert!(decode_frame(0, &[1, 255]).is_err());
        assert!(decode_frame(5, &[6, 1, 0, 0, 0]).is_err());
        assert!(decode_frame(1, &[0; 36]).is_err());
    }

    #[test]
    fn handles_fragmented_and_coalesced_streams_and_matches_verdict_wire_bytes() -> io::Result<()> {
        struct Fragmented(Cursor<Vec<u8>>);
        impl Read for Fragmented {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let length = buffer.len().min(1);
                self.0.read(&mut buffer[..length])
            }
        }
        let frame = vec![0, 3, 0, 0, 0, 3, b'o', b'k'];
        let mut fragmented = Fragmented(Cursor::new([frame.clone(), frame].concat()));
        for _ in 0..2 {
            assert_eq!(
                read_event(&mut fragmented)?,
                Some(Event::Log {
                    severity: 3,
                    message: "ok".to_owned()
                })
            );
        }
        assert!(read_event(&mut fragmented)?.is_none());
        assert_eq!(verdict_command(1, Verdict::Accept), [1, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(verdict_command(u64::MAX, Verdict::Block)[9], 4);
        Ok(())
    }
}
