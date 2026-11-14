#![allow(dead_code)] // sebagian helper encoder baru dipakai di fase berikutnya

use crate::tokens::tokens;
use anyhow::{anyhow, bail, Result};
use std::io::Read;

pub const LIST_EMPTY: u8 = 0;
pub const DICT_0: u8 = 236;
pub const DICT_3: u8 = 239;
pub const FB_JID: u8 = 246;
pub const AD_JID: u8 = 247;
pub const LIST_8: u8 = 248;
pub const LIST_16: u8 = 249;
pub const JID_PAIR: u8 = 250;
pub const HEX_8: u8 = 251;
pub const BINARY_8: u8 = 252;
pub const BINARY_20: u8 = 253;
pub const BINARY_32: u8 = 254;
pub const NIBBLE_8: u8 = 255;

#[derive(Debug, Clone)]
pub enum Content {
    None,
    Nodes(Vec<Node>),
    Bytes(Vec<u8>),
    Text(String),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub content: Content,
}

impl Node {
    pub fn new(tag: &str, attrs: &[(&str, &str)], content: Content) -> Self {
        Node {
            tag: tag.to_string(),
            attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            content,
        }
    }

    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn children(&self) -> &[Node] {
        match &self.content {
            Content::Nodes(v) => v,
            _ => &[],
        }
    }

    pub fn child(&self, tag: &str) -> Option<&Node> {
        self.children().iter().find(|c| c.tag == tag)
    }

    pub fn text(&self) -> String {
        match &self.content {
            Content::Text(s) => s.clone(),
            Content::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        }
    }

    pub fn dump(&self, depth: usize, out: &mut String) {
        let pad = "  ".repeat(depth);
        out.push_str(&format!("{pad}<{}", self.tag));
        for (k, v) in &self.attrs {
            out.push_str(&format!(" {k}=\"{v}\""));
        }
        match &self.content {
            Content::None => out.push_str("/>\n"),
            Content::Text(s) => {
                let t: String = s.chars().take(60).collect();
                out.push_str(&format!(">{t}</{}>\n", self.tag));
            }
            Content::Bytes(b) => {
                let printable = b.iter().all(|c| (0x20..0x7f).contains(c));
                let shown = if printable {
                    String::from_utf8_lossy(&b[..b.len().min(24)]).into_owned()
                } else {
                    hex::encode(&b[..b.len().min(16)])
                };
                out.push_str(&format!("> [{}B] {shown}</{}>\n", b.len(), self.tag));
            }
            Content::Nodes(v) => {
                out.push_str(">\n");
                for c in v {
                    c.dump(depth + 1, out);
                }
                out.push_str(&format!("{pad}</{}>\n", self.tag));
            }
        }
    }
}

// ======================= DECODER =======================

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or_else(|| anyhow!("EOF di posisi {}", self.pos))?;
        self.pos += 1;
        Ok(b)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            bail!("EOF: butuh {n} byte di posisi {}", self.pos);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn int(&mut self, n: usize) -> Result<usize> {
        let mut v = 0usize;
        for _ in 0..n {
            v = (v << 8) | self.byte()? as usize;
        }
        Ok(v)
    }
    fn int20(&mut self) -> Result<usize> {
        let a = self.byte()? as usize;
        let b = self.byte()? as usize;
        let c = self.byte()? as usize;
        Ok(((a & 15) << 16) + (b << 8) + c)
    }
}

fn unpack(t: u8, v: u8) -> Result<char> {
    match (t, v) {
        (_, 0..=9) => Ok((b'0' + v) as char),
        (NIBBLE_8, 10) => Ok('-'),
        (NIBBLE_8, 11) => Ok('.'),
        (NIBBLE_8, 15) => Ok('\0'),
        (HEX_8, 10..=15) => Ok((b'A' + v - 10) as char),
        _ => bail!("nibble tidak valid: {v}"),
    }
}

fn read_packed8(r: &mut Reader, t: u8) -> Result<String> {
    let start = r.byte()?;
    let mut s = String::new();
    for _ in 0..(start & 127) {
        let b = r.byte()?;
        s.push(unpack(t, b >> 4)?);
        s.push(unpack(t, b & 15)?);
    }
    if start >> 7 != 0 {
        s.pop();
    }
    Ok(s)
}

fn read_string(r: &mut Reader, t: u8) -> Result<String> {
    let tk = tokens();
    if t >= 1 && (t as usize) < tk.single.len().min(236) {
        return Ok(tk.single[t as usize].clone());
    }
    match t {
        DICT_0..=DICT_3 => {
            let d = (t - DICT_0) as usize;
            let i = r.byte()? as usize;
            tk.double
                .get(d)
                .and_then(|x| x.get(i))
                .cloned()
                .ok_or_else(|| anyhow!("token ganda tidak valid ({d},{i})"))
        }
        LIST_EMPTY => Ok(String::new()),
        BINARY_8 => {
            let n = r.byte()? as usize;
            Ok(String::from_utf8_lossy(r.take(n)?).into_owned())
        }
        BINARY_20 => {
            let n = r.int20()?;
            Ok(String::from_utf8_lossy(r.take(n)?).into_owned())
        }
        BINARY_32 => {
            let n = r.int(4)?;
            Ok(String::from_utf8_lossy(r.take(n)?).into_owned())
        }
        JID_PAIR => {
            let a = r.byte()?;
            let user = read_string(r, a)?;
            let b = r.byte()?;
            let server = read_string(r, b)?;
            if server.is_empty() {
                bail!("JID_PAIR tanpa server");
            }
            Ok(format!("{user}@{server}"))
        }
        AD_JID => {
            let domain = r.byte()?;
            let device = r.byte()?;
            let u = r.byte()?;
            let user = read_string(r, u)?;
            let server = match domain {
                1 => "lid",
                128 => "hosted",
                129 => "hosted.lid",
                _ => "s.whatsapp.net",
            };
            if device > 0 {
                Ok(format!("{user}:{device}@{server}"))
            } else {
                Ok(format!("{user}@{server}"))
            }
        }
        FB_JID => {
            let u = r.byte()?;
            let user = read_string(r, u)?;
            let device = r.int(2)?;
            let s = r.byte()?;
            let server = read_string(r, s)?;
            Ok(format!("{user}:{device}@{server}"))
        }
        HEX_8 | NIBBLE_8 => read_packed8(r, t),
        _ => bail!("tag tidak dikenal: {t}"),
    }
}

fn read_list_size(r: &mut Reader, t: u8) -> Result<usize> {
    match t {
        LIST_EMPTY => Ok(0),
        LIST_8 => Ok(r.byte()? as usize),
        LIST_16 => r.int(2),
        _ => bail!("tag ukuran list tidak valid: {t}"),
    }
}

fn decode_node(r: &mut Reader) -> Result<Node> {
    let st = r.byte()?;
    let list_size = read_list_size(r, st)?;
    let ht = r.byte()?;
    let header = read_string(r, ht)?;
    if list_size == 0 || header.is_empty() {
        bail!("node tidak valid");
    }
    let mut attrs = Vec::new();
    for _ in 0..((list_size - 1) >> 1) {
        let kt = r.byte()?;
        let k = read_string(r, kt)?;
        let vt = r.byte()?;
        let v = read_string(r, vt)?;
        attrs.push((k, v));
    }
    let content = if list_size % 2 == 0 {
        let t = r.byte()?;
        if matches!(t, LIST_EMPTY | LIST_8 | LIST_16) {
            let n = read_list_size(r, t)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(decode_node(r)?);
            }
            Content::Nodes(v)
        } else {
            match t {
                BINARY_8 => {
                    let n = r.byte()? as usize;
                    Content::Bytes(r.take(n)?.to_vec())
                }
                BINARY_20 => {
                    let n = r.int20()?;
                    Content::Bytes(r.take(n)?.to_vec())
                }
                BINARY_32 => {
                    let n = r.int(4)?;
                    Content::Bytes(r.take(n)?.to_vec())
                }
                _ => Content::Text(read_string(r, t)?),
            }
        }
    } else {
        Content::None
    };
    Ok(Node { tag: header, attrs, content })
}

/// Decode satu frame hasil dekripsi Noise (byte pertama = flag, bit 2 = zlib).
pub fn decode_frame(data: &[u8]) -> Result<Node> {
    let flag = *data.first().ok_or_else(|| anyhow!("frame kosong"))?;
    let body: Vec<u8> = if flag & 2 != 0 {
        let mut d = flate2::read::ZlibDecoder::new(&data[1..]);
        let mut o = Vec::new();
        d.read_to_end(&mut o)?;
        o
    } else {
        data[1..].to_vec()
    };
    let mut r = Reader { buf: &body, pos: 0 };
    decode_node(&mut r)
}

// ======================= ENCODER =======================

fn write_list_start(out: &mut Vec<u8>, n: usize) {
    if n == 0 {
        out.push(LIST_EMPTY);
    } else if n < 256 {
        out.push(LIST_8);
        out.push(n as u8);
    } else {
        out.push(LIST_16);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
}

fn write_byte_length(out: &mut Vec<u8>, n: usize) {
    if n >= (1 << 20) {
        out.push(BINARY_32);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else if n >= 256 {
        out.push(BINARY_20);
        out.push(((n >> 16) & 15) as u8);
        out.push(((n >> 8) & 255) as u8);
        out.push((n & 255) as u8);
    } else {
        out.push(BINARY_8);
        out.push(n as u8);
    }
}

fn pack_nibble(c: u8) -> u8 {
    match c {
        b'-' => 10,
        b'.' => 11,
        0 => 15,
        b'0'..=b'9' => c - b'0',
        _ => 0,
    }
}

fn pack_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => 10 + c - b'A',
        0 => 15,
        _ => 0,
    }
}

fn write_packed(out: &mut Vec<u8>, s: &str, t: u8) {
    let b = s.as_bytes();
    let pack = |c: u8| if t == NIBBLE_8 { pack_nibble(c) } else { pack_hex(c) };
    out.push(t);
    let mut rounded = b.len().div_ceil(2) as u8;
    if b.len() % 2 != 0 {
        rounded |= 128;
    }
    out.push(rounded);
    for pair in b.chunks(2) {
        let hi = pack(pair[0]);
        let lo = if pair.len() == 2 { pack(pair[1]) } else { pack(0) };
        out.push((hi << 4) | lo);
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    if s.is_empty() {
        out.extend_from_slice(&[BINARY_8, 0]);
        return;
    }
    if let Some(&(dict, idx)) = tokens().map.get(s) {
        if let Some(d) = dict {
            out.push(DICT_0 + d);
        }
        out.push(idx);
        return;
    }
    let b = s.as_bytes();
    if b.len() <= 127 && b.iter().all(|c| c.is_ascii_digit() || *c == b'-' || *c == b'.') {
        write_packed(out, s, NIBBLE_8);
        return;
    }
    if b.len() <= 127 && b.iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c)) {
        write_packed(out, s, HEX_8);
        return;
    }
    if let Some((user, server)) = s.split_once('@') {
        if let Some((u, dev)) = user.split_once(':') {
            let domain = match server {
                "lid" => 1,
                "hosted" => 128,
                "hosted.lid" => 129,
                _ => 0,
            };
            out.push(AD_JID);
            out.push(domain);
            out.push(dev.parse::<u8>().unwrap_or(0));
            write_string(out, u);
        } else {
            out.push(JID_PAIR);
            if user.is_empty() {
                out.push(LIST_EMPTY);
            } else {
                write_string(out, user);
            }
            write_string(out, server);
        }
        return;
    }
    write_byte_length(out, b.len());
    out.extend_from_slice(b);
}

fn write_node(out: &mut Vec<u8>, n: &Node) {
    let has_content = !matches!(n.content, Content::None);
    write_list_start(out, 2 * n.attrs.len() + 1 + has_content as usize);
    write_string(out, &n.tag);
    for (k, v) in &n.attrs {
        write_string(out, k);
        write_string(out, v);
    }
    match &n.content {
        Content::None => {}
        Content::Text(s) => write_string(out, s),
        Content::Bytes(b) => {
            write_byte_length(out, b.len());
            out.extend_from_slice(b);
        }
        Content::Nodes(v) => {
            write_list_start(out, v.len());
            for c in v {
                write_node(out, c);
            }
        }
    }
}

/// Encode node jadi byte siap dienkripsi Noise (byte pertama = flag 0).
pub fn encode_node(n: &Node) -> Vec<u8> {
    let mut out = vec![0u8];
    write_node(&mut out, n);
    out
}
