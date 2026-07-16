use std::net::TcpStream;
use std::io::{Read, Write};
use tungstenite::{WebSocket, stream::MaybeTlsStream};
use crate::crypto::SecureSession;

pub enum RawConnection {
    Tcp(TcpStream),
    WebSocket(WebSocket<MaybeTlsStream<TcpStream>>),
}

fn write_all_nonblocking(stream: &mut TcpStream, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "failed to write whole buffer")),
            Ok(n) => {
                data = &data[n..];
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl RawConnection {
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            RawConnection::Tcp(stream) => stream.set_nonblocking(nonblocking),
            RawConnection::WebSocket(ws) => {
                match ws.get_ref() {
                    MaybeTlsStream::Plain(s) => s.set_nonblocking(nonblocking),
                    MaybeTlsStream::Rustls(s) => s.get_ref().set_nonblocking(nonblocking),
                    _ => Ok(()),
                }
            }
        }
    }

    pub fn read_packet(&mut self) -> Result<Option<Vec<u8>>, &'static str> {
        match self {
            RawConnection::Tcp(stream) => {
                let mut len_buf = [0u8; 4];
                match stream.read_exact(&mut len_buf) {
                    Ok(_) => {
                        let len = u32::from_be_bytes(len_buf) as usize;
                        let mut payload = vec![0u8; len];
                        stream.read_exact(&mut payload).map_err(|_| "TCP read payload failed")?;
                        Ok(Some(payload))
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                    Err(_) => Err("TCP connection closed"),
                }
            }
            RawConnection::WebSocket(ws) => {
                match ws.read() {
                    Ok(tungstenite::Message::Binary(data)) => Ok(Some(data)),
                    Ok(_) => Ok(None),
                    Err(tungstenite::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                    Err(_) => Err("WS connection closed"),
                }
            }
        }
    }

    pub fn write_packet(&mut self, data: &[u8]) -> Result<(), &'static str> {
        match self {
            RawConnection::Tcp(stream) => {
                let len = data.len() as u32;
                write_all_nonblocking(stream, &len.to_be_bytes()).map_err(|_| "TCP write prefix failed")?;
                write_all_nonblocking(stream, data).map_err(|_| "TCP write payload failed")
            }
            RawConnection::WebSocket(ws) => {
                match ws.send(tungstenite::Message::Binary(data.to_vec())) {
                    Ok(_) => Ok(()),
                    Err(tungstenite::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        loop {
                            match ws.flush() {
                                Ok(_) => return Ok(()),
                                Err(tungstenite::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(std::time::Duration::from_millis(5));
                                }
                                Err(_) => return Err("WS write failed"),
                            }
                        }
                    }
                    Err(_) => Err("WS write failed"),
                }
            }
        }
    }
}

pub fn listen_tcp(port: u16) -> Result<RawConnection, &'static str> {
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|_| "Failed to bind port")?;
    let (stream, _) = listener.accept().map_err(|_| "Accept failed")?;
    let _ = stream.set_nodelay(true);
    Ok(RawConnection::Tcp(stream))
}

pub fn connect_tcp(addr: &str) -> Result<RawConnection, &'static str> {
    let stream = std::net::TcpStream::connect(addr)
        .map_err(|_| "Failed to connect to peer")?;
    let _ = stream.set_nodelay(true);
    Ok(RawConnection::Tcp(stream))
}

pub fn connect_ws(url_str: &str) -> Result<RawConnection, Box<dyn std::error::Error>> {
    let url = url::Url::parse(url_str)?;
    let (ws, _) = tungstenite::connect(url)?;
    Ok(RawConnection::WebSocket(ws))
}

pub fn perform_handshake(mut conn: RawConnection) -> Result<(RawConnection, SecureSession), &'static str> {
    let (secret, our_public) = crate::crypto::generate_ephemeral_keypair();

    // Send our public key
    match &mut conn {
        RawConnection::Tcp(stream) => {
            stream.write_all(&our_public).map_err(|_| "Handshake write failed")?;
        }
        RawConnection::WebSocket(ws) => {
            ws.send(tungstenite::Message::Binary(our_public.to_vec())).map_err(|_| "Handshake write failed")?;
        }
    }

    // Receive peer public key
    let mut peer_public = [0u8; 32];
    match &mut conn {
        RawConnection::Tcp(stream) => {
            stream.read_exact(&mut peer_public).map_err(|_| "Handshake read failed")?;
        }
        RawConnection::WebSocket(ws) => {
            loop {
                match ws.read() {
                    Ok(tungstenite::Message::Binary(bytes)) => {
                        if bytes.len() == 32 {
                            peer_public.copy_from_slice(&bytes);
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return Err("Handshake WS closed"),
                }
            }
        }
    }

    let session = SecureSession::new(secret, peer_public);
    Ok((conn, session))
}
