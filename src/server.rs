// listener: listens on address, accepts things, spawns tasks to handle connection
// connection handler struct has arc for shared state
// need a sniffer to determine what protocol is being used
// sniffer needs a way to replay the sniffed chunk(s)
// for TLS, match b"\x16\x03\x01" (type = handshake, version = TLS 1.0),
//   skip two bytes (length), then b"\x01" (type = client hello)
// for HTTP/2, match b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (last part probably optional)
// for HTTP/1, match methods: GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
//   also try to match r"^[A-Za-z0-9]+\s+[^\r\n]+\s+HTTP/\d" in first chunk maybe
// otherwise, assume it's HTTP/1 anyways?

pub struct Listener {}

impl Listener {
    pub fn new() -> Self {
        todo!();
    }
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum PreambleState {
    INIT,
    TLS,
    CONNECT,
    DELETE,
    GET,
    HEAD,
    OPTIONS,
    P0,
    HTTP2, // PRI
    POST,
    PUT,
    PATCH,
    TRACE, // perhaps handle this one locally for fun
    REJECT,
    ACCEPT_TLS,
    ACCEPT_HTTP1,
    ACCEPT_HTTP2,
}

pub struct BigFunnyStateMachine {
    state: PreambleState,
    index: usize,
}

impl BigFunnyStateMachine {
    pub fn new() -> Self {
        BigFunnyStateMachine {
            state: PreambleState::INIT,
            index: 0,
        }
    }

    pub fn next(self, byte: u8) -> Self {
        use PreambleState::*;

        macro_rules! literal_state {
            ($state:ident, $idx:ident, $byte:ident, $pattern:literal, $accept:ident) => {{
                if let Some(&v) = $pattern.get($idx) {
                    if $byte == v {
                        if $idx == $pattern.len() - 1 {
                            $accept
                        } else {
                            $state
                        }
                    } else {
                        REJECT
                    }
                } else {
                    REJECT
                }
            }};
        }

        let next_state = match (self.state, self.index, byte) {
            (INIT, 0, 0x16) => TLS,
            (INIT, 0, b'C') => CONNECT,
            (INIT, 0, b'D') => DELETE,
            (INIT, 0, b'G') => GET,
            (INIT, 0, b'H') => HEAD,
            (INIT, 0, b'O') => OPTIONS,
            (INIT, 0, b'P') => P0,
            (INIT, 0, b'T') => TRACE,
            (INIT, 0, _) => REJECT,
            (INIT, _, _) => unreachable!("bad INIT state"),
            (_, 0, _) => unreachable!("state should be INIT"),
            (TLS, 1, 0x03) => TLS,
            (TLS, 2, 0x01) => TLS,
            (TLS, 3 | 4, _) => TLS,
            (TLS, 5, 0x01) => ACCEPT_TLS,
            (TLS, _, _) => REJECT,
            (P0, 1, b'O') => POST,
            (P0, 1, b'U') => PUT,
            (P0, 1, b'A') => PATCH,
            (P0, 1, b'R') => HTTP2,
            (P0, 1, _) => REJECT,
            (P0, _, _) => unreachable!("bad P0 state"),
            (CONNECT, idx, byte) => literal_state!(CONNECT, idx, byte, b"CONNECT ", ACCEPT_HTTP1),
            (DELETE, idx, byte) => literal_state!(DELETE, idx, byte, b"DELETE ", ACCEPT_HTTP1),
            (GET, idx, byte) => literal_state!(GET, idx, byte, b"GET ", ACCEPT_HTTP1),
            (HEAD, idx, byte) => literal_state!(HEAD, idx, byte, b"HEAD ", ACCEPT_HTTP1),
            (OPTIONS, idx, byte) => literal_state!(OPTIONS, idx, byte, b"OPTIONS ", ACCEPT_HTTP1),
            (HTTP2, idx, byte) => {
                literal_state!(
                    HTTP2,
                    idx,
                    byte,
                    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                    ACCEPT_HTTP2
                )
            }
            (POST, idx, byte) => literal_state!(POST, idx, byte, b"POST ", ACCEPT_HTTP1),
            (PUT, idx, byte) => literal_state!(PUT, idx, byte, b"PUT ", ACCEPT_HTTP1),
            (PATCH, idx, byte) => literal_state!(PATCH, idx, byte, b"PATCH ", ACCEPT_HTTP1),
            (TRACE, idx, byte) => literal_state!(TRACE, idx, byte, b"TRACE ", ACCEPT_HTTP1),
            (REJECT | ACCEPT_TLS | ACCEPT_HTTP1 | ACCEPT_HTTP2, _, _) => {
                unreachable!("did not exit after final state")
            }
        };

        BigFunnyStateMachine {
            state: next_state,
            index: self.index + 1,
        }
    }
}

impl Default for BigFunnyStateMachine {
    fn default() -> Self {
        Self::new()
    }
}
