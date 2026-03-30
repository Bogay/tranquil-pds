use cid::Cid;
use futures::stream::StreamExt;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite};
use tokio_util::sync::CancellationToken;
use tranquil_scopes::RepoAction;

#[derive(Debug)]
pub enum FirehoseFrame {
    Commit(Box<ParsedCommitFrame>),
    Identity(IdentityData),
    Account(AccountData),
    Info(InfoData),
    Error(ErrorData),
    Unknown(Vec<u8>),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedCommitFrame {
    pub seq: i64,
    pub repo: String,
    pub commit: Cid,
    pub rev: String,
    pub since: Option<String>,
    pub blocks: Vec<u8>,
    pub ops: Vec<ParsedRepoOp>,
    pub blobs: Vec<Cid>,
    pub time: String,
    pub prev_data: Option<Cid>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedRepoOp {
    pub action: RepoAction,
    pub path: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct IdentityData {
    pub did: String,
    pub seq: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AccountData {
    pub did: String,
    pub seq: i64,
    pub active: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct InfoData {
    pub name: String,
    pub message: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ErrorData {
    pub error: String,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFrameHeader {
    op: i64,
    #[serde(default)]
    t: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCommitBody {
    seq: i64,
    repo: String,
    commit: Cid,
    rev: String,
    since: Option<String>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: Vec<RawOp>,
    #[serde(default)]
    blobs: Vec<Cid>,
    time: String,
    #[serde(rename = "prevData")]
    prev_data: Option<Cid>,
}

#[derive(Debug, Deserialize)]
struct RawOp {
    action: RepoAction,
    path: String,
    cid: Option<Cid>,
    prev: Option<Cid>,
}

#[derive(Debug, Deserialize)]
struct RawIdentityBody {
    did: String,
    seq: i64,
}

#[derive(Debug, Deserialize)]
struct RawAccountBody {
    did: String,
    seq: i64,
    active: bool,
}

#[derive(Debug, Deserialize)]
struct RawInfoBody {
    name: String,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawErrorBody {
    error: String,
    message: Option<String>,
}

pub struct FirehoseConsumer {
    frames: Arc<Mutex<Vec<FirehoseFrame>>>,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl FirehoseConsumer {
    pub async fn connect_with_cursor(port: u16, cursor: i64) -> Self {
        Self::connect_inner(port, Some(cursor)).await
    }

    async fn connect_inner(port: u16, cursor: Option<i64>) -> Self {
        let url = match cursor {
            Some(c) => format!(
                "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos?cursor={}",
                port, c
            ),
            None => format!(
                "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
                port
            ),
        };
        let (ws_stream, _) = connect_async(&url)
            .await
            .expect("Failed to connect to firehose");
        let frames: Arc<Mutex<Vec<FirehoseFrame>>> = Arc::new(Mutex::new(Vec::new()));
        let cancel = CancellationToken::new();

        let frames_clone = frames.clone();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            let (_, mut read) = ws_stream.split();
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    msg = read.next() => {
                        match msg {
                            Some(Ok(tungstenite::Message::Binary(bin))) => {
                                let frame = parse_frame_bytes(&bin);
                                frames_clone.lock().unwrap().push(frame);
                            }
                            Some(Ok(tungstenite::Message::Close(_))) | None => break,
                            _ => {}
                        }
                    }
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        Self {
            frames,
            cancel,
            handle,
        }
    }

    pub async fn wait_for_commits(
        &self,
        did: &str,
        count: usize,
        timeout: std::time::Duration,
    ) -> Vec<ParsedCommitFrame> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let matching: Vec<ParsedCommitFrame> = self
                .frames
                .lock()
                .unwrap()
                .iter()
                .filter_map(|f| match f {
                    FirehoseFrame::Commit(c) if c.repo == did => Some(ParsedCommitFrame::clone(c)),
                    _ => None,
                })
                .collect();
            if matching.len() >= count {
                return matching;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "Timed out waiting for {} commits for DID {}, got {}",
                    count,
                    did,
                    matching.len()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    #[allow(dead_code)]
    pub fn all_frames(&self) -> Vec<FirehoseFrame> {
        self.frames.lock().unwrap().drain(..).collect()
    }

    #[allow(dead_code)]
    pub fn all_commits(&self) -> Vec<ParsedCommitFrame> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter_map(|f| match f {
                FirehoseFrame::Commit(c) => Some(ParsedCommitFrame::clone(c)),
                _ => None,
            })
            .collect()
    }
}

impl Drop for FirehoseConsumer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

impl Clone for FirehoseFrame {
    fn clone(&self) -> Self {
        match self {
            Self::Commit(c) => Self::Commit(c.clone()),
            Self::Identity(i) => Self::Identity(i.clone()),
            Self::Account(a) => Self::Account(a.clone()),
            Self::Info(i) => Self::Info(i.clone()),
            Self::Error(e) => Self::Error(e.clone()),
            Self::Unknown(b) => Self::Unknown(b.clone()),
        }
    }
}

fn find_cbor_map_end(bytes: &[u8]) -> Result<usize, String> {
    let mut pos = 0;

    fn read_uint(bytes: &[u8], pos: &mut usize, additional: u8) -> Result<u64, String> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                if *pos >= bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = bytes[*pos] as u64;
                *pos += 1;
                Ok(val)
            }
            25 => {
                if *pos + 2 > bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as u64;
                *pos += 2;
                Ok(val)
            }
            26 => {
                if *pos + 4 > bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = u32::from_be_bytes([
                    bytes[*pos],
                    bytes[*pos + 1],
                    bytes[*pos + 2],
                    bytes[*pos + 3],
                ]) as u64;
                *pos += 4;
                Ok(val)
            }
            27 => {
                if *pos + 8 > bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = u64::from_be_bytes([
                    bytes[*pos],
                    bytes[*pos + 1],
                    bytes[*pos + 2],
                    bytes[*pos + 3],
                    bytes[*pos + 4],
                    bytes[*pos + 5],
                    bytes[*pos + 6],
                    bytes[*pos + 7],
                ]);
                *pos += 8;
                Ok(val)
            }
            _ => Err(format!("Invalid additional info: {}", additional)),
        }
    }

    fn skip_value(bytes: &[u8], pos: &mut usize) -> Result<(), String> {
        if *pos >= bytes.len() {
            return Err("Unexpected end".into());
        }
        let initial = bytes[*pos];
        *pos += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;

        match major {
            0 | 1 => {
                read_uint(bytes, pos, additional)?;
                Ok(())
            }
            2 | 3 => {
                let len = read_uint(bytes, pos, additional)? as usize;
                *pos += len;
                Ok(())
            }
            4 => {
                let len = read_uint(bytes, pos, additional)?;
                (0..len).try_for_each(|_| skip_value(bytes, pos))
            }
            5 => {
                let len = read_uint(bytes, pos, additional)?;
                (0..len).try_for_each(|_| {
                    skip_value(bytes, pos)?;
                    skip_value(bytes, pos)
                })
            }
            6 => {
                read_uint(bytes, pos, additional)?;
                skip_value(bytes, pos)
            }
            7 => Ok(()),
            _ => Err(format!("Unknown major type: {}", major)),
        }
    }

    skip_value(bytes, &mut pos)?;
    Ok(pos)
}

pub fn parse_frame_bytes(raw: &[u8]) -> FirehoseFrame {
    let header_end = match find_cbor_map_end(raw) {
        Ok(e) => e,
        Err(_) => return FirehoseFrame::Unknown(raw.to_vec()),
    };

    let header: RawFrameHeader = match serde_ipld_dagcbor::from_slice(&raw[..header_end]) {
        Ok(h) => h,
        Err(_) => return FirehoseFrame::Unknown(raw.to_vec()),
    };

    let body = &raw[header_end..];

    if header.op == -1 {
        return serde_ipld_dagcbor::from_slice::<RawErrorBody>(body)
            .map(|b| {
                FirehoseFrame::Error(ErrorData {
                    error: b.error,
                    message: b.message,
                })
            })
            .unwrap_or_else(|_| FirehoseFrame::Unknown(raw.to_vec()));
    }

    match header.t.as_deref() {
        Some("#commit") => serde_ipld_dagcbor::from_slice::<RawCommitBody>(body)
            .map(|b| {
                FirehoseFrame::Commit(Box::new(ParsedCommitFrame {
                    seq: b.seq,
                    repo: b.repo,
                    commit: b.commit,
                    rev: b.rev,
                    since: b.since,
                    blocks: b.blocks,
                    ops: b
                        .ops
                        .into_iter()
                        .map(|op| ParsedRepoOp {
                            action: op.action,
                            path: op.path,
                            cid: op.cid,
                            prev: op.prev,
                        })
                        .collect(),
                    blobs: b.blobs,
                    time: b.time,
                    prev_data: b.prev_data,
                }))
            })
            .unwrap_or_else(|_| FirehoseFrame::Unknown(raw.to_vec())),
        Some("#identity") => serde_ipld_dagcbor::from_slice::<RawIdentityBody>(body)
            .map(|b| {
                FirehoseFrame::Identity(IdentityData {
                    did: b.did,
                    seq: b.seq,
                })
            })
            .unwrap_or_else(|_| FirehoseFrame::Unknown(raw.to_vec())),
        Some("#account") => serde_ipld_dagcbor::from_slice::<RawAccountBody>(body)
            .map(|b| {
                FirehoseFrame::Account(AccountData {
                    did: b.did,
                    seq: b.seq,
                    active: b.active,
                })
            })
            .unwrap_or_else(|_| FirehoseFrame::Unknown(raw.to_vec())),
        Some("#info") => serde_ipld_dagcbor::from_slice::<RawInfoBody>(body)
            .map(|b| {
                FirehoseFrame::Info(InfoData {
                    name: b.name,
                    message: b.message,
                })
            })
            .unwrap_or_else(|_| FirehoseFrame::Unknown(raw.to_vec())),
        _ => FirehoseFrame::Unknown(raw.to_vec()),
    }
}
