//! HX3: QR-code transport for air-gapped FROST signing (Mode B).
//!
//! Everything crossing the air gap is wrapped in a fixed "HX3" frame that the
//! receiver validates strictly before any key material is touched. Frames are
//! self-describing (magic, version, type, session, index, total, checksum) and
//! are moved:

use sha2::{Digest, Sha256};

use crate::Error;

/// Magic bytes identifying an HX3 frame ("Horcrux 3").
pub const HX3_MAGIC: &[u8] = b"HX3";

/// Current HX3 wire version. The receiver rejects any other version.
pub const HX3_VERSION: u8 = 1;

/// Length of the session identifier in bytes.
pub const SESSION_LEN: usize = 16;

/// Length of the fixed HX3 header in bytes.
pub const HEADER_LEN: usize = 3 + 1 + 1 + SESSION_LEN + 2 + 2 + 4 + 4;

/// Length of the trailing SHA-256 truncation checksum in bytes.
pub const CHECKSUM_LEN: usize = 4;

/// Maximum payload bytes carried by a single frame. Kept deliberately small so
/// every frame renders as a scannable QR code.
pub const MAX_FRAME_PAYLOAD: usize = 450;

/// Maximum number of frames per message (255 because frame index/total are u16,
/// and the air-gap UX collapses beyond a couple of frames anyway).
pub const MAX_FRAMES: u16 = 255;

/// Maximum payload bytes across all frames of one message.
pub const MAX_MESSAGE_PAYLOAD: usize = MAX_FRAME_PAYLOAD * MAX_FRAMES as usize;

/// The four HX3 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Coordinator -> participants: "please sign this message".
    Request = 1,
    /// Participant -> coordinator: "I am willing to sign it" (round 1).
    Commitment = 2,
    /// Coordinator -> participants: the assembled signing package (round 2).
    SigningPackage = 3,
    /// Participant -> coordinator: the finished signature share (round 2).
    SignatureShare = 4,
    /// Encrypted HORCRUX share file transport.
    EncryptedShard = 5,
}

impl MessageType {
    /// Parse a raw type byte, rejecting anything unknown.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(MessageType::Request),
            2 => Some(MessageType::Commitment),
            3 => Some(MessageType::SigningPackage),
            4 => Some(MessageType::SignatureShare),
            5 => Some(MessageType::EncryptedShard),
            _ => None,
        }
    }

    /// The serialized type byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A single self-contained HX3 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// What kind of message this frame belongs to.
    pub message_type: MessageType,
    /// 16-byte session identifier binding all frames of one signing attempt.
    pub session: [u8; SESSION_LEN],
    /// Zero-based position of this frame within the message.
    pub index: u16,
    /// Total number of frames in the message.
    pub total: u16,
    /// The chunk of payload carried by this frame.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Serialize to the full HX3 wire format (header + checksum + payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(HX3_MAGIC);
        out.push(HX3_VERSION);
        out.push(self.message_type.to_u8());
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&checksum(
            &self.session,
            self.index,
            self.total,
            &self.payload,
        ));
        out.extend_from_slice(&self.payload);
        out
    }

    /// Strictly parse one frame from the wire format. Any inconsistency
    /// (wrong magic, wrong version, unknown type, truncated fields, oversized
    /// payload, length/checksum mismatch) is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Frame, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Hx3(format!(
                "frame is only {} bytes, need at least {HEADER_LEN}",
                bytes.len()
            )));
        }
        if &bytes[0..3] != HX3_MAGIC {
            return Err(Error::Hx3("bad magic, not an HX3 frame".into()));
        }
        if bytes[3] != HX3_VERSION {
            return Err(Error::Hx3(format!(
                "unsupported version {}, need {HX3_VERSION}",
                bytes[3]
            )));
        }
        let message_type = MessageType::from_u8(bytes[4])
            .ok_or_else(|| Error::Hx3(format!("unknown message type {}", bytes[4])))?;
        let session: [u8; SESSION_LEN] = bytes[5..5 + SESSION_LEN].try_into().unwrap();
        let index = u16::from_le_bytes(bytes[21..23].try_into().unwrap());
        let total = u16::from_le_bytes(bytes[23..25].try_into().unwrap());
        let payload_len = u32::from_le_bytes(bytes[25..29].try_into().unwrap()) as usize;

        if total == 0 {
            return Err(Error::Hx3("frame total is zero".into()));
        }
        if index >= total {
            return Err(Error::Hx3(format!(
                "frame index {index} out of range for total {total}"
            )));
        }
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(Error::Hx3(format!(
                "frame payload of {payload_len} bytes exceeds the limit of {MAX_FRAME_PAYLOAD}"
            )));
        }
        let header_end = HEADER_LEN;
        if bytes.len() != header_end + payload_len {
            return Err(Error::Hx3(format!(
                "declared payload of {payload_len} bytes but frame holds {}",
                bytes.len() - header_end
            )));
        }
        let stored_checksum: [u8; CHECKSUM_LEN] = bytes[29..29 + CHECKSUM_LEN].try_into().unwrap();
        let computed_checksum = checksum(&session, index, total, &bytes[header_end..]);
        if stored_checksum != computed_checksum {
            return Err(Error::Hx3(
                "frame checksum mismatch (corrupt or tampered data)".into(),
            ));
        }

        Ok(Frame {
            message_type,
            session,
            index,
            total,
            payload: bytes[header_end..].to_vec(),
        })
    }

    /// Render the frame as base58 text (compact, unambiguous characters) ready
    /// to be encoded into a QR code.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// Parse a frame from its base58 text representation.
    pub fn from_base58(text: &str) -> Result<Frame, Error> {
        let bytes = bs58::decode(text)
            .into_vec()
            .map_err(|e| Error::Hx3(format!("invalid base58 frame: {e}")))?;
        Frame::from_bytes(&bytes)
    }
}

/// SHA-256 truncation checksum binding a frame's identity to its payload.
fn checksum(
    session: &[u8; SESSION_LEN],
    index: u16,
    total: u16,
    payload: &[u8],
) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(session);
    hasher.update(index.to_le_bytes());
    hasher.update(total.to_le_bytes());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Split a payload into 0-based frames of at most `MAX_FRAME_PAYLOAD` bytes.
pub fn encode_message(
    message_type: MessageType,
    session: [u8; SESSION_LEN],
    payload: &[u8],
) -> Result<Vec<Frame>, Error> {
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(Error::Hx3(format!(
            "message payload of {} bytes exceeds the limit of {MAX_MESSAGE_PAYLOAD}",
            payload.len()
        )));
    }
    let total = payload.len().div_ceil(MAX_FRAME_PAYLOAD);
    let total = u16::try_from(total).map_err(|_| Error::Hx3("too many frames".into()))?;
    let mut frames = Vec::with_capacity(total as usize);
    for (index, chunk) in payload.chunks(MAX_FRAME_PAYLOAD).enumerate() {
        frames.push(Frame {
            message_type,
            session,
            index: index as u16,
            total,
            payload: chunk.to_vec(),
        });
    }
    // A zero-length payload still produces one valid (empty) frame so the
    // message never disappears.
    if frames.is_empty() {
        frames.push(Frame {
            message_type,
            session,
            index: 0,
            total: 1,
            payload: Vec::new(),
        });
    }
    Ok(frames)
}

/// Concatenate frames into a `.hx3` file payload (header + checksum + payload
/// per frame, back to back).
pub fn serialize_frames(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        out.extend_from_slice(&frame.to_bytes());
    }
    out
}

/// Parse `.hx3` file bytes into a frame list, validating every frame.
pub fn deserialize_frames(bytes: &[u8]) -> Result<Vec<Frame>, Error> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN {
            return Err(Error::Hx3(format!(
                "trailing {} bytes too short for a frame header",
                bytes.len() - offset
            )));
        }
        if &bytes[offset..offset + 3] != HX3_MAGIC {
            return Err(Error::Hx3(
                "bad magic at frame start; not an HX3 frame set".into(),
            ));
        }
        if bytes[offset + 3] != HX3_VERSION {
            return Err(Error::Hx3("unsupported HX3 version in frame set".into()));
        }
        let payload_len =
            u32::from_le_bytes(bytes[offset + 25..offset + 29].try_into().unwrap()) as usize;
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(Error::Hx3(format!(
                "frame payload of {payload_len} bytes exceeds the limit of {MAX_FRAME_PAYLOAD}"
            )));
        }
        let frame_end = offset
            .checked_add(HEADER_LEN)
            .and_then(|end| end.checked_add(payload_len))
            .ok_or_else(|| Error::Hx3("frame set length overflow".into()))?;
        if frame_end > bytes.len() {
            return Err(Error::Hx3("truncated frame at end of file".into()));
        }
        let frame = Frame::from_bytes(&bytes[offset..frame_end])?;
        frames.push(frame);
        offset = frame_end;
    }
    Ok(frames)
}

/// Reassemble a complete message from its frames.
///
/// Requires:
/// * all frames share the same type, session and total;
/// * the set contains every index exactly once;
/// * no index is out of range.
///
/// Frame order is irrelevant (frames are positional by index).
pub fn assemble_message(
    frames: &[Frame],
) -> Result<(MessageType, [u8; SESSION_LEN], Vec<u8>), Error> {
    if frames.is_empty() {
        return Err(Error::Hx3("no frames to assemble".into()));
    }
    let message_type = frames[0].message_type;
    let session = frames[0].session;
    let total = frames[0].total as usize;
    if total == 0 {
        return Err(Error::Hx3("message total is zero".into()));
    }
    if frames.len() != total {
        return Err(Error::Hx3(format!(
            "incomplete message: have {} frames, expected {total}",
            frames.len()
        )));
    }
    let mut slots: Vec<Option<&[u8]>> = vec![None; total];
    let mut capacity = 0usize;
    for frame in frames {
        if frame.message_type != message_type {
            return Err(Error::Hx3("message mixes different frame types".into()));
        }
        if frame.session != session {
            return Err(Error::Hx3("message mixes different sessions".into()));
        }
        if frame.total as usize != total {
            return Err(Error::Hx3("frame disagree on message total".into()));
        }
        let index = frame.index as usize;
        if index >= total {
            return Err(Error::Hx3(format!(
                "frame index {index} out of range for total {total}"
            )));
        }
        if slots[index].is_some() {
            return Err(Error::Hx3(format!("duplicate frame index {index}")));
        }
        slots[index] = Some(&frame.payload);
        capacity += frame.payload.len();
    }
    let mut payload = Vec::with_capacity(capacity);
    for slot in &slots {
        payload.extend_from_slice(slot.expect("validated complete"));
    }
    Ok((message_type, session, payload))
}

/// Binary header of a PNG file, used to auto-detect QR images by content.
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Encode a single frame as an in-memory PNG QR code image.
///
/// The QR encodes the frame's base58 text (byte mode). `scale` is the pixel
/// size of each module, and a standard quiet zone of four modules is added.
pub fn encode_qr_png_bytes(frame: &Frame, scale: u32) -> Result<Vec<u8>, Error> {
    let text = frame.to_base58();
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| Error::Qr(format!("failed to encode QR code: {e}")))?;
    let module_count = code.width() as u32;
    let quiet = 4u32;
    let size = module_count + quiet * 2;
    let pixels = size * scale;

    let mut img = image::GrayImage::from_pixel(pixels, pixels, image::Luma([255u8]));
    for (row, module_row) in code.to_colors().chunks_exact(code.width()).enumerate() {
        for (col, color) in module_row.iter().enumerate() {
            if color == &qrcode::Color::Dark {
                let x = (col as u32 + quiet) * scale;
                let y = (row as u32 + quiet) * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        img.put_pixel(x + dx, y + dy, image::Luma([0u8]));
                    }
                }
            }
        }
    }

    let mut bytes = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut bytes),
        image::ImageFormat::Png,
    )
    .map_err(|e| Error::Qr(format!("failed to encode QR PNG: {e}")))?;
    Ok(bytes)
}

/// Encode a single frame as a PNG QR code saved to `path`.
pub fn write_qr_png(frame: &Frame, path: &std::path::Path, scale: u32) -> Result<(), Error> {
    let bytes = encode_qr_png_bytes(frame, scale)?;
    std::fs::write(path, bytes)
        .map_err(|e| Error::Qr(format!("failed to write QR image {}: {e}", path.display())))
}

/// Decode a single frame from in-memory PNG QR code image bytes.
pub fn decode_qr_png_bytes(bytes: &[u8]) -> Result<Frame, Error> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| Error::Qr(format!("failed to read QR image: {e}")))?
        .to_luma8();
    let (width, height) = (img.width() as usize, img.height() as usize);
    let mut grid = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        img.get_pixel(x as u32, y as u32)[0]
    });
    let (_, text) = grid
        .detect_grids()
        .iter_mut()
        .find_map(|g| g.decode().ok())
        .ok_or_else(|| Error::Qr("no decodable QR code found in image".into()))?;
    Frame::from_base58(&text)
}

/// Decode a single frame from a PNG QR code image file.
pub fn read_qr_png(path: &std::path::Path) -> Result<Frame, Error> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Qr(format!("failed to read image {}: {e}", path.display())))?;
    decode_qr_png_bytes(&bytes)
}

/// Extract the encrypted shard/share payload from a single-frame QR image.
pub fn shard_payload_from_frame(frame: &Frame) -> Result<Vec<u8>, Error> {
    if frame.message_type != MessageType::EncryptedShard {
        return Err(Error::Qr(
            "QR image does not contain an encrypted shard/share".into(),
        ));
    }
    if frame.total != 1 {
        return Err(Error::Qr(format!(
            "QR image carries frame {}/{}; shard/share imports must be single-frame",
            frame.index + 1,
            frame.total
        )));
    }
    Ok(frame.payload.clone())
}

/// Extract the encrypted shard/share payload from a QR PNG file.
pub fn shard_payload_from_qr_png(path: &std::path::Path) -> Result<Vec<u8>, Error> {
    let frame = read_qr_png(path)?;
    shard_payload_from_frame(&frame)
}

/// Extract the encrypted shard/share payload from in-memory QR PNG bytes.
pub fn shard_payload_from_qr_png_bytes(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let frame = decode_qr_png_bytes(bytes)?;
    shard_payload_from_frame(&frame)
}

/// Stage an encrypted shard/share payload as a uniquely named `.hx` file in
/// `dir`, returning its path.
pub fn stage_shard_payload(
    payload: &[u8],
    dir: &std::path::Path,
) -> Result<std::path::PathBuf, Error> {
    std::fs::create_dir_all(dir).map_err(Error::Io)?;
    let unique: [u8; 8] = rand::random();
    let path = dir.join(format!("horcrux-qr-import-{}.hx", hex::encode(unique)));
    std::fs::write(&path, payload).map_err(Error::Io)?;
    Ok(path)
}

/// Stage a single-frame shard/share QR PNG to a temporary `.hx` file.
pub fn stage_shard_from_qr_png(path: &std::path::Path) -> Result<std::path::PathBuf, Error> {
    let payload = shard_payload_from_qr_png(path)?;
    stage_shard_payload(&payload, &std::env::temp_dir())
}

/// Stage a single-frame shard/share QR PNG, provided as bytes, to a temporary
/// `.hx` file.
pub fn stage_shard_from_qr_png_bytes(bytes: &[u8]) -> Result<std::path::PathBuf, Error> {
    let payload = shard_payload_from_qr_png_bytes(bytes)?;
    stage_shard_payload(&payload, &std::env::temp_dir())
}

/// Render one frame as a printable QR code using unicode half-blocks. A quiet
/// zone of four light modules surrounds the symbol on every side. A code of
/// width `W` prints as `W + 8` columns and `(W + 8) / 2` lines; counting
/// half-blocks, that is exactly `W` modules wide and `W` modules tall, so it
/// scans like the underlying symbol.
pub fn terminal_qr(frame: &Frame) -> String {
    use qrcode::Color;

    let text = frame.to_base58();
    let code = qrcode::QrCode::new(text.as_bytes()).expect("frame base58 always fits a QR");
    let width = code.width() as i32;
    let quiet = 4i32;
    let colors = code.to_colors();

    let cell = |col: i32, row: i32| -> bool {
        if col < 0 || row < 0 || col >= width || row >= width {
            false
        } else {
            colors[row as usize * code.width() + col as usize] == Color::Dark
        }
    };

    let mut out = String::new();
    let total_columns = width + 2 * quiet;
    let mut module_row = -quiet;
    while module_row < width {
        for col in -quiet..total_columns - quiet {
            let top = cell(col, module_row);
            let bottom = cell(col, module_row + 1);
            let ch = match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        out.push('\n');
        module_row += 2;
    }
    out
}

/// Write a complete message as a `.hx3` file and return the serialized bytes.
pub fn write_message_file(
    path: &std::path::Path,
    message_type: MessageType,
    session: [u8; SESSION_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let frames = encode_message(message_type, session, payload)?;
    let bytes = serialize_frames(&frames);
    std::fs::write(path, &bytes).map_err(Error::Io)?;
    Ok(bytes)
}

/// Read a message file, auto-detecting a PNG QR image (single frame) or an
/// `.hx3` frame collection, then reassembling the full message.
pub fn read_message_file(
    path: &std::path::Path,
) -> Result<(MessageType, [u8; SESSION_LEN], Vec<u8>), Error> {
    if is_png_file(path) {
        let frame = read_qr_png(path)?;
        if frame.total != 1 {
            return Err(Error::Hx3(format!(
                "QR image carries frame {}/{}; multi-frame messages need a .hx3 file",
                frame.index + 1,
                frame.total
            )));
        }
        return Ok((frame.message_type, frame.session, frame.payload));
    }
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let frames = deserialize_frames(&bytes)?;
    assemble_message(&frames)
}

/// True if the file starts with a PNG signature.
fn is_png_file(path: &std::path::Path) -> bool {
    let Ok(head) = std::fs::read(path) else {
        return false;
    };
    head.len() >= PNG_MAGIC.len() && &head[..PNG_MAGIC.len()] == PNG_MAGIC
}

/// How a message crosses the air gap: as a set of scannable QR-code PNGs (the
/// literal "photograph the code" path), or as a single `.hx3` file (a
/// stand-in for physically carrying a file, e.g. on a USB drive, when a
/// camera isn't available — the same convention [`crate::mpc`] already uses
/// for share files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// One PNG QR code per frame.
    Qr,
    /// A single `.hx3` frame-collection file.
    Hx3,
}

/// Pixel size of each QR module when rendering [`Transport::Qr`] output. Large
/// enough to scan reliably from a phone camera at arm's length.
const QR_SCALE: u32 = 6;

/// Write a complete message across the air gap into `dir`, named by `prefix`:
/// either one QR PNG per frame (`{prefix}-{index}.png`) or a single `.hx3`
/// collection (`{prefix}.hx3`). Returns the written file paths.
pub fn write_message_transport(
    dir: &std::path::Path,
    prefix: &str,
    format: Transport,
    message_type: MessageType,
    session: [u8; SESSION_LEN],
    payload: &[u8],
) -> Result<Vec<std::path::PathBuf>, Error> {
    std::fs::create_dir_all(dir).map_err(Error::Io)?;
    let frames = encode_message(message_type, session, payload)?;
    match format {
        Transport::Hx3 => {
            let path = dir.join(format!("{prefix}.hx3"));
            std::fs::write(&path, serialize_frames(&frames)).map_err(Error::Io)?;
            Ok(vec![path])
        }
        Transport::Qr => frames
            .iter()
            .map(|frame| {
                let path = dir.join(format!("{prefix}-{}.png", frame.index));
                write_qr_png(frame, &path, QR_SCALE)?;
                Ok(path)
            })
            .collect(),
    }
}

/// Read a complete message written by [`write_message_transport`] under
/// `prefix` in `dir`, auto-detecting a `.hx3` file or a set of QR PNGs.
pub fn read_message_transport(
    dir: &std::path::Path,
    prefix: &str,
) -> Result<(MessageType, [u8; SESSION_LEN], Vec<u8>), Error> {
    let hx3_path = dir.join(format!("{prefix}.hx3"));
    if hx3_path.is_file() {
        return read_message_file(&hx3_path);
    }
    let png_prefix = format!("{prefix}-");
    let png_paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(Error::Io)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&png_prefix) && n.ends_with(".png"))
        })
        .collect();
    if png_paths.is_empty() {
        return Err(Error::Hx3(format!(
            "no {prefix}.hx3 or {prefix}-*.png found in {}",
            dir.display()
        )));
    }
    // Order is irrelevant: assemble_message places each frame by its own
    // index, not by input order.
    let frames: Vec<Frame> = png_paths
        .iter()
        .map(|p| read_qr_png(p))
        .collect::<Result<_, _>>()?;
    assemble_message(&frames)
}

/// List the distinct participant ids present in `dir` for a multi-participant
/// prefix stem (e.g. `"commit"` or `"share"`): scans for `{stem}-{id}.hx3` and
/// `{stem}-{id}-{index}.png`. Used by the coordinator to discover which
/// participants have responded without needing an out-of-band roster.
pub fn list_participant_ids(dir: &std::path::Path, stem: &str) -> Result<Vec<u8>, Error> {
    let mut ids = std::collections::BTreeSet::new();
    let file_prefix = format!("{stem}-");
    for entry in std::fs::read_dir(dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&file_prefix) else {
            continue;
        };
        let id_token = rest.split(['-', '.']).next().unwrap_or("");
        if let Ok(id) = id_token.parse::<u8>() {
            ids.insert(id);
        }
    }
    Ok(ids.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> [u8; SESSION_LEN] {
        [0x42; SESSION_LEN]
    }

    #[test]
    fn frame_wire_round_trip() {
        let frame = Frame {
            message_type: MessageType::Commitment,
            session: session(),
            index: 0,
            total: 1,
            payload: b"hello frame".to_vec(),
        };
        let bytes = frame.to_bytes();
        assert_eq!(Frame::from_bytes(&bytes).expect("parse"), frame);
    }

    #[test]
    fn base58_round_trip() {
        let frame = Frame {
            message_type: MessageType::SignatureShare,
            session: session(),
            index: 2,
            total: 5,
            payload: vec![1, 2, 3, 4, 5],
        };
        let text = frame.to_base58();
        assert_eq!(Frame::from_base58(&text).expect("parse"), frame);
    }

    #[test]
    fn small_message_is_a_single_frame() {
        let frames = encode_message(MessageType::Request, session(), b"tiny").expect("encode");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].total, 1);
        let (ty, sess, payload) = assemble_message(&frames).expect("assemble");
        assert_eq!(ty, MessageType::Request);
        assert_eq!(sess, session());
        assert_eq!(payload, b"tiny");
    }

    #[test]
    fn large_message_splits_into_multiple_frames_and_reassembles() {
        let payload: Vec<u8> = (0..(MAX_FRAME_PAYLOAD * 3 + 17))
            .map(|i| (i % 256) as u8)
            .collect();
        let frames = encode_message(MessageType::SigningPackage, session(), &payload)
            .expect("encode large message");
        assert_eq!(frames.len(), 4, "3 full frames + 1 partial frame");
        assert!(frames.iter().all(|f| f.total == 4));

        // Reassembly must not depend on frame order.
        let mut shuffled = frames.clone();
        shuffled.reverse();
        let (ty, sess, reassembled) = assemble_message(&shuffled).expect("assemble");
        assert_eq!(ty, MessageType::SigningPackage);
        assert_eq!(sess, session());
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn assemble_rejects_incomplete_or_mismatched_frames() {
        let payload = vec![7u8; MAX_FRAME_PAYLOAD * 2 + 1];
        let frames = encode_message(MessageType::Commitment, session(), &payload).expect("encode");
        assert_eq!(frames.len(), 3);

        // Missing a frame.
        assert!(assemble_message(&frames[..2]).is_err());

        // Mismatched session.
        let mut bad = frames.clone();
        bad[0].session = [0xAA; SESSION_LEN];
        assert!(assemble_message(&bad).is_err());
    }

    #[test]
    fn hx3_file_round_trip_multi_frame() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![9u8; MAX_FRAME_PAYLOAD * 2 + 30];
        let path = dir.path().join("msg.hx3");
        write_message_file(&path, MessageType::Request, session(), &payload).expect("write");
        let (ty, sess, read_back) = read_message_file(&path).expect("read");
        assert_eq!(ty, MessageType::Request);
        assert_eq!(sess, session());
        assert_eq!(read_back, payload);
    }

    #[test]
    fn qr_png_round_trip_at_max_frame_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![0x5Au8; MAX_FRAME_PAYLOAD];
        let frames = encode_message(MessageType::Request, session(), &payload).expect("encode");
        assert_eq!(frames.len(), 1, "must fit in exactly one frame");

        let path = dir.path().join("frame.png");
        write_qr_png(&frames[0], &path, 4).expect("write qr png");
        let decoded = read_qr_png(&path).expect("decode qr png");
        assert_eq!(decoded, frames[0]);
    }

    #[test]
    fn message_transport_hx3_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = b"a signing request payload".to_vec();
        write_message_transport(
            dir.path(),
            "request",
            Transport::Hx3,
            MessageType::Request,
            session(),
            &payload,
        )
        .expect("write");
        let (ty, sess, read_back) = read_message_transport(dir.path(), "request").expect("read");
        assert_eq!(ty, MessageType::Request);
        assert_eq!(sess, session());
        assert_eq!(read_back, payload);
    }

    #[test]
    fn message_transport_qr_round_trip_multi_frame() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![0x11u8; MAX_FRAME_PAYLOAD + 40];
        let paths = write_message_transport(
            dir.path(),
            "package",
            Transport::Qr,
            MessageType::SigningPackage,
            session(),
            &payload,
        )
        .expect("write");
        assert_eq!(paths.len(), 2, "payload needs two QR frames");
        assert!(paths.iter().all(|p| p.extension().unwrap() == "png"));

        let (ty, sess, read_back) = read_message_transport(dir.path(), "package").expect("read");
        assert_eq!(ty, MessageType::SigningPackage);
        assert_eq!(sess, session());
        assert_eq!(read_back, payload);
    }

    #[test]
    fn list_participant_ids_scans_both_transports() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_message_transport(
            dir.path(),
            "commit-1",
            Transport::Hx3,
            MessageType::Commitment,
            session(),
            b"c1",
        )
        .expect("write 1");
        write_message_transport(
            dir.path(),
            "commit-3",
            Transport::Qr,
            MessageType::Commitment,
            session(),
            b"c3",
        )
        .expect("write 3");

        let ids = list_participant_ids(dir.path(), "commit").expect("list");
        assert_eq!(ids, vec![1, 3]);
    }

    #[test]
    fn shard_payload_round_trips_through_png_and_staging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![0x77u8; 83];
        let paths = write_message_transport(
            dir.path(),
            "shard-1-qr",
            Transport::Qr,
            MessageType::EncryptedShard,
            session(),
            &payload,
        )
        .expect("write shard qr");
        assert_eq!(paths.len(), 1);

        let extracted = shard_payload_from_qr_png(&paths[0]).expect("extract payload");
        assert_eq!(extracted, payload);
        assert_eq!(
            shard_payload_from_qr_png_bytes(&std::fs::read(&paths[0]).expect("read png"))
                .expect("extract bytes"),
            payload
        );

        let staged = stage_shard_payload(&extracted, dir.path()).expect("stage");
        assert_eq!(std::fs::read(&staged).expect("read staged"), payload);
    }

    #[test]
    fn shard_payload_rejects_non_shard_qr() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-shard.png");
        write_qr_png(
            &Frame {
                message_type: MessageType::Request,
                session: session(),
                index: 0,
                total: 1,
                payload: b"not a shard".to_vec(),
            },
            &path,
            4,
        )
        .expect("write qr");
        assert!(shard_payload_from_qr_png(&path).is_err());
    }

    #[test]
    fn shard_payload_rejects_multi_frame_qr() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("multi.png");
        write_qr_png(
            &Frame {
                message_type: MessageType::EncryptedShard,
                session: session(),
                index: 0,
                total: 2,
                payload: b"first half".to_vec(),
            },
            &path,
            4,
        )
        .expect("write qr");
        assert!(shard_payload_from_qr_png(&path).is_err());
    }

    #[test]
    fn qr_png_bytes_round_trip() {
        let frame = Frame {
            message_type: MessageType::Request,
            session: session(),
            index: 0,
            total: 1,
            payload: b"byte level round trip".to_vec(),
        };
        let bytes = encode_qr_png_bytes(&frame, 4).expect("encode bytes");
        let decoded = decode_qr_png_bytes(&bytes).expect("decode bytes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn terminal_qr_renders_a_non_empty_grid() {
        let frame = Frame {
            message_type: MessageType::Request,
            session: session(),
            index: 0,
            total: 1,
            payload: b"terminal".to_vec(),
        };
        let rendered = terminal_qr(&frame);
        assert!(!rendered.is_empty());
        assert!(rendered.contains('\n'));
    }
}
