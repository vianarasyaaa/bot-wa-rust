mod adv;
mod binary;
mod creds;
mod crypto;
mod noise;
mod pairing;
mod proto;
mod signal;
mod storage;
mod tokens;
mod wamsg;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use md5::{Digest, Md5};
use prost::Message as _;
use std::io::Write;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
};

use crate::binary::{decode_frame, encode_node, Content, Node};
use crate::creds::Creds;
use crate::crypto::{dh, random_bytes, KeyPair};
use crate::noise::Noise;
use crate::proto::*;
use crate::signal::Store;
use crate::wamsg::{LoginPayload, Message as WaMessage};

const WS_URL: &str = "wss://web.whatsapp.com/ws/chat";
const CREDS_PATH: &str = "auth/creds.json";
const SIGNAL_PATH: &str = "auth/signal.json";
const FALLBACK_REV: u32 = 1023223821;
const PREKEY_BATCH: u32 = 100;
const MIN_PREKEYS: u32 = 20;

enum Exit {
    Restart,
    Stop,
}

fn parse_rev(s: &str) -> Option<u32> {
    let i = s.find("client_revision")?;
    let rest = &s[i + "client_revision".len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn wa_version() -> [u32; 3] {
    if let Ok(v) = std::env::var("WA_VERSION") {
        let p: Vec<u32> = v.split('.').filter_map(|x| x.parse().ok()).collect();
        if p.len() == 3 {
            return [p[0], p[1], p[2]];
        }
    }
    let out = Command::new("curl")
        .args([
            "-sL", "--max-time", "10",
            "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "-H", "sec-fetch-site: none",
            "https://web.whatsapp.com/sw.js",
        ])
        .output();
    if let Ok(o) = out {
        if let Some(rev) = parse_rev(&String::from_utf8_lossy(&o.stdout)) {
            return [2, 3000, rev];
        }
    }
    eprintln!("[!] gagal ambil versi terbaru, pakai fallback (mungkin ditolak server)");
    [2, 3000, FALLBACK_REV]
}

fn k32(b: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(b).map_err(|_| anyhow!("kunci harus 32 byte, dapat {}", b.len()))
}

fn be_bytes(v: u32, n: usize) -> Vec<u8> {
    v.to_be_bytes()[4 - n..].to_vec()
}

fn user_agent(ver: [u32; 3]) -> UserAgent {
    UserAgent {
        platform: Some(14), // WEB
        app_version: Some(AppVersion {
            primary: Some(ver[0]),
            secondary: Some(ver[1]),
            tertiary: Some(ver[2]),
        }),
        mcc: Some("000".into()),
        mnc: Some("000".into()),
        os_version: Some("0.1".into()),
        manufacturer: Some("".into()),
        device: Some("Desktop".into()),
        os_build_number: Some("0.1".into()),
        release_channel: Some(0),
        locale_language: Some("en".into()),
        locale_country: Some("US".into()),
    }
}

fn registration_payload(c: &Creds, ver: [u32; 3]) -> ClientPayload {
    let device_props = DeviceProps {
        os: Some("Ubuntu".into()),
        version: Some(AppVersion { primary: Some(10), secondary: Some(15), tertiary: Some(7) }),
        platform_type: Some(1), // CHROME
        require_full_sync: Some(false),
    }
    .encode_to_vec();
    let build_hash = Md5::digest(format!("{}.{}.{}", ver[0], ver[1], ver[2]).as_bytes()).to_vec();

    ClientPayload {
        passive: Some(false),
        pull: Some(false),
        connect_type: Some(1),
        connect_reason: Some(1),
        user_agent: Some(user_agent(ver)),
        web_info: Some(WebInfo { web_sub_platform: Some(0) }),
        device_pairing_data: Some(DevicePairingData {
            e_regid: Some(be_bytes(c.reg_id, 4)),
            e_keytype: Some(vec![5]),
            e_ident: Some(c.identity.public.to_vec()),
            e_skey_id: Some(be_bytes(c.spk_id, 3)),
            e_skey_val: Some(c.spk.public.to_vec()),
            e_skey_sig: Some(c.spk_sig.to_vec()),
            build_hash: Some(build_hash),
            device_props: Some(device_props),
        }),
    }
}

fn login_payload(c: &Creds, ver: [u32; 3]) -> Result<LoginPayload> {
    let jid = c.me_jid.as_deref().ok_or_else(|| anyhow!("me_jid kosong di creds.json"))?;
    let left = jid.split('@').next().unwrap_or("");
    let (user, dev) = left.split_once(':').unwrap_or((left, "0"));
    let user = user.split('_').next().unwrap_or(user);
    Ok(LoginPayload {
        username: Some(user.parse().context("nomor di JID tidak valid")?),
        device: Some(dev.parse().unwrap_or(0)),
        passive: Some(true),
        pull: Some(true),
        connect_type: Some(1),
        connect_reason: Some(1),
        user_agent: Some(user_agent(ver)),
        web_info: Some(WebInfo { web_sub_platform: Some(0) }),
    })
}

fn preview(b: &[u8]) -> String {
    hex::encode(&b[..b.len().min(32)])
}

fn brief(n: &Node) -> String {
    let attrs: Vec<String> = n.attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let kids: Vec<&str> = n.children().iter().map(|c| c.tag.as_str()).take(4).collect();
    if kids.is_empty() {
        format!("{} {}", n.tag, attrs.join(" "))
    } else {
        format!("{} {} [{}]", n.tag, attrs.join(" "), kids.join(","))
    }
}

async fn send_node<S>(tx: &mut S, noise: &mut Noise, node: &Node) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let frame = noise.encode_frame(&encode_node(node))?;
    tx.send(Message::Binary(frame)).await?;
    Ok(())
}

fn ask_phone() -> Result<Option<String>> {
    let raw = match std::env::args().nth(1) {
        Some(a) => a,
        None => {
            print!("Nomor WA + kode negara (contoh 628123456789): ");
            std::io::stdout().flush()?;
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s
        }
    };
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Ok(None);
    }
    if digits.starts_with('0') || digits.len() < 8 || digits.len() > 15 {
        bail!("nomor harus format internasional tanpa 0 di depan, contoh 628123456789");
    }
    Ok(Some(digits))
}

fn ack_for(node: &Node) -> Node {
    let mut a = vec![
        ("id", node.attr("id").unwrap_or("")),
        ("class", node.tag.as_str()),
    ];
    if let Some(t) = node.attr("from") {
        a.push(("to", t));
    }
    if let Some(p) = node.attr("participant") {
        a.push(("participant", p));
    }
    if let Some(r) = node.attr("recipient") {
        a.push(("recipient", r));
    }
    if node.tag != "message" {
        if let Some(t) = node.attr("type") {
            a.push(("type", t));
        }
    }
    Node::new("ack", &a, Content::None)
}

fn iq(id: &str, typ: &str, xmlns: &str, content: Vec<Node>) -> Node {
    Node::new(
        "iq",
        &[("id", id), ("to", "s.whatsapp.net"), ("type", typ), ("xmlns", xmlns)],
        Content::Nodes(content),
    )
}

// ---------- helper JID / padding ----------

fn user_of(jid: &str) -> &str {
    let left = jid.split('@').next().unwrap_or(jid);
    left.split(':').next().unwrap_or(left)
}

fn chat_jid(from: &str) -> String {
    let server = from.split_once('@').map(|x| x.1).unwrap_or("s.whatsapp.net");
    format!("{}@{}", user_of(from), server)
}

fn signal_addr(jid: &str) -> String {
    let (left, server) = jid.split_once('@').unwrap_or((jid, ""));
    let (user, dev) = left.split_once(':').unwrap_or((left, "0"));
    format!("{user}.{dev}@{server}")
}

fn pad(mut v: Vec<u8>) -> Vec<u8> {
    let mut n = (random_bytes::<1>()[0] & 0x0f) as usize;
    if n == 0 {
        n = 16;
    }
    v.extend(std::iter::repeat(n as u8).take(n));
    v
}

fn unpad(v: &[u8]) -> Result<&[u8]> {
    let n = *v.last().ok_or_else(|| anyhow!("plaintext kosong"))? as usize;
    if n == 0 || n > v.len() {
        bail!("padding tidak valid");
    }
    Ok(&v[..v.len() - n])
}

fn bot_reply(text: &str) -> Option<String> {
    match text.trim().to_lowercase().as_str() {
        "!ping" => Some("pong 🏓 dari bot WhatsApp Rust native".into()),
        "!halo" | "halo" => Some("Halo! Aku bot WhatsApp yang ditulis Rust native 🦀".into()),
        "!help" => Some("Perintah: !ping, !halo, !help".into()),
        _ => None,
    }
}

// ---------- prekey ----------

async fn upload_prekeys<S>(tx: &mut S, noise: &mut Noise, creds: &Creds, store: &mut Store) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let keys = store.gen_prekeys(PREKEY_BATCH);
    store.save(SIGNAL_PATH)?;
    let list: Vec<Node> = keys
        .iter()
        .map(|(id, public)| {
            Node::new(
                "key",
                &[],
                Content::Nodes(vec![
                    Node::new("id", &[], Content::Bytes(be_bytes(*id, 3))),
                    Node::new("value", &[], Content::Bytes(public.to_vec())),
                ]),
            )
        })
        .collect();
    let skey = Node::new(
        "skey",
        &[],
        Content::Nodes(vec![
            Node::new("id", &[], Content::Bytes(be_bytes(creds.spk_id, 3))),
            Node::new("value", &[], Content::Bytes(creds.spk.public.to_vec())),
            Node::new("signature", &[], Content::Bytes(creds.spk_sig.to_vec())),
        ]),
    );
    let node = iq(
        "wars.upk",
        "set",
        "encrypt",
        vec![
            Node::new("registration", &[], Content::Bytes(be_bytes(creds.reg_id, 4))),
            Node::new("type", &[], Content::Bytes(vec![5])),
            Node::new("identity", &[], Content::Bytes(creds.identity.public.to_vec())),
            Node::new("list", &[], Content::Nodes(list)),
            skey,
        ],
    );
    send_node(tx, noise, &node).await?;
    println!("[>] upload {} prekey ke server", keys.len());
    Ok(())
}

// ---------- pesan masuk / keluar ----------

async fn send_text<S>(
    tx: &mut S,
    noise: &mut Noise,
    creds: &Creds,
    store: &mut Store,
    chat: &str,
    author: &str,
    text: &str,
) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let addr = signal_addr(author);
    let msg = WaMessage { conversation: Some(text.to_string()), ..Default::default() };
    let plain = pad(msg.encode_to_vec());
    let enc = store.encrypt(&addr, &plain, creds)?;
    store.save(SIGNAL_PATH)?;
    let id = format!("3EB0{}", hex::encode_upper(random_bytes::<18>()));
    let node = Node::new(
        "message",
        &[("id", id.as_str()), ("to", chat), ("type", "text")],
        Content::Nodes(vec![Node::new(
            "participants",
            &[],
            Content::Nodes(vec![Node::new(
                "to",
                &[("jid", author)],
                Content::Nodes(vec![Node::new(
                    "enc",
                    &[("v", "2"), ("type", "msg")],
                    Content::Bytes(enc),
                )]),
            )]),
        )]),
    );
    send_node(tx, noise, &node).await?;
    println!("[>] balasan terkirim ke {author}: {text}");
    Ok(())
}

async fn on_message<S>(tx: &mut S, noise: &mut Noise, creds: &Creds, store: &mut Store, node: &Node) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let from = node.attr("from").unwrap_or("").to_string();
    let author = node.attr("participant").unwrap_or(&from).to_string();
    let id = node.attr("id").unwrap_or("").to_string();
    let mut text: Option<String> = None;

    for enc in node.children().iter().filter(|c| c.tag == "enc") {
        let kind = enc.attr("type").unwrap_or("");
        let data = match &enc.content {
            Content::Bytes(b) => b.clone(),
            _ => continue,
        };
        match kind {
            "pkmsg" | "msg" => match store.decrypt(&signal_addr(&author), kind, &data, creds) {
                Ok(pt) => {
                    store.save(SIGNAL_PATH)?;
                    match unpad(&pt).and_then(|p| Ok(WaMessage::decode(p)?)) {
                        Ok(m) => {
                            text = m
                                .conversation
                                .or_else(|| m.extended_text_message.and_then(|e| e.text));
                        }
                        Err(e) => println!("[!] gagal baca isi pesan: {e}"),
                    }
                }
                Err(e) => println!("[!] gagal dekripsi {kind} dari {author}: {e}"),
            },
            "skmsg" => println!("[i] pesan grup (sender key) dari {author}: belum didukung"),
            other => println!("[i] tipe enc tidak dikenal: {other}"),
        }
    }

    send_node(tx, noise, &ack_for(node)).await?;
    let mut ra = vec![("id", id.as_str()), ("to", from.as_str())];
    if let Some(p) = node.attr("participant") {
        ra.push(("participant", p));
    }
    send_node(tx, noise, &Node::new("receipt", &ra, Content::None)).await?;

    if let Some(t) = text {
        println!("[msg] {author}: {t}");
        let sender = user_of(&author);
        let is_self = Some(sender) == creds.me_jid.as_deref().map(user_of)
            || Some(sender) == creds.me_lid.as_deref().map(user_of);
        if !is_self {
            if let Some(reply) = bot_reply(&t) {
                if let Err(e) = send_text(tx, noise, creds, store, &chat_jid(&from), &author, &reply).await {
                    println!("[!] gagal kirim balasan: {e}");
                }
            }
        }
    }
    Ok(())
}

// ---------- satu sesi koneksi ----------

async fn run_session(creds: &mut Creds, store: &mut Store, phone: Option<&str>, ver: [u32; 3]) -> Result<Exit> {
    let registered = creds.registered;
    let pairing = if registered { None } else { phone.map(pairing::PairingState::new) };
    if !registered && pairing.is_none() {
        bail!("nomor WA wajib diisi untuk pairing code");
    }
    let payload_bytes = if registered {
        login_payload(creds, ver)?.encode_to_vec()
    } else {
        registration_payload(creds, ver).encode_to_vec()
    };

    let t0 = Instant::now();
    let mut req = WS_URL.into_client_request()?;
    req.headers_mut()
        .insert("Origin", HeaderValue::from_static("https://web.whatsapp.com"));
    let (ws, _) = connect_async(req).await.context("gagal konek WebSocket")?;
    let (mut tx, mut rx) = ws.split();
    println!("[+] WebSocket tersambung ({:.0} ms)", t0.elapsed().as_secs_f64() * 1000.0);

    let t1 = Instant::now();
    let eph = KeyPair::generate();
    let mut noise = Noise::new(&eph.public);
    let hello = HandshakeMessage {
        client_hello: Some(ClientHello { ephemeral: Some(eph.public.to_vec()), ..Default::default() }),
        ..Default::default()
    };
    let frame = noise.encode_frame(&hello.encode_to_vec())?;
    tx.send(Message::Binary(frame)).await?;
    println!("[>] ClientHello terkirim ({})", if registered { "login" } else { "registrasi" });

    let mut handshake_done = false;
    let mut hello_sent = false;
    let mut code_deadline: Option<Instant> = None;
    let mut paired_at: Option<Instant> = None;
    let mut logged_in = false;
    let mut last_ping = Instant::now();
    let mut ping_n = 0u32;
    let mut id_n = 0u32;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            msg = rx.next() => {
                let msg = match msg {
                    Some(m) => m?,
                    None => {
                        if paired_at.is_some() { return Ok(Exit::Restart); }
                        bail!("server menutup koneksi")
                    }
                };
                match msg {
                    Message::Binary(data) => {
                        for f in noise.feed(&data) {
                            if !handshake_done {
                                let sh = HandshakeMessage::decode(f.as_slice())?
                                    .server_hello
                                    .ok_or_else(|| anyhow!("balasan pertama bukan ServerHello"))?;
                                let s_eph = k32(sh.ephemeral.as_deref().unwrap_or_default())?;
                                let s_static_enc = sh.static_key.unwrap_or_default();
                                let s_payload_enc = sh.payload.unwrap_or_default();

                                noise.authenticate(&s_eph);
                                noise.mix_into_key(&dh(&eph.private, &s_eph));
                                let s_static = k32(&noise.decrypt(&s_static_enc)?)?;
                                noise.mix_into_key(&dh(&eph.private, &s_static));
                                let _cert = noise.decrypt(&s_payload_enc)?;

                                let key_enc = noise.encrypt(&creds.noise.public)?;
                                noise.mix_into_key(&dh(&creds.noise.private, &s_eph));
                                let payload_enc = noise.encrypt(&payload_bytes)?;

                                let fin = HandshakeMessage {
                                    client_finish: Some(ClientFinish {
                                        static_key: Some(key_enc),
                                        payload: Some(payload_enc),
                                    }),
                                    ..Default::default()
                                };
                                let out = noise.encode_frame(&fin.encode_to_vec())?;
                                tx.send(Message::Binary(out)).await?;
                                noise.finish_init();
                                handshake_done = true;
                                println!("[>] handshake Noise selesai ({:.0} ms)", t1.elapsed().as_secs_f64() * 1000.0);
                                continue;
                            }

                            let pt = noise.decrypt(&f)?;
                            let node = match decode_frame(&pt) {
                                Ok(n) => n,
                                Err(e) => {
                                    println!("[!] gagal decode frame ({} byte): {e} | {}", pt.len(), preview(&pt));
                                    continue;
                                }
                            };
                            if std::env::var("WA_DEBUG").is_ok() {
                                let mut s = String::new();
                                node.dump(1, &mut s);
                                println!("[<] node:\n{s}");
                            } else {
                                println!("[<] {}", brief(&node));
                            }

                            match node.tag.as_str() {
                                "iq" => {
                                    if node.child("pair-device").is_some() {
                                        send_node(&mut tx, &mut noise, &Node::new(
                                            "iq",
                                            &[("to", "s.whatsapp.net"), ("type", "result"), ("id", node.attr("id").unwrap_or(""))],
                                            Content::None,
                                        )).await?;
                                        if let Some(st) = &pairing {
                                            if !hello_sent {
                                                id_n += 1;
                                                let h = pairing::companion_hello(st, &creds.noise.public, &format!("wars.{id_n}"));
                                                send_node(&mut tx, &mut noise, &h).await?;
                                                hello_sent = true;
                                                code_deadline = Some(Instant::now() + Duration::from_secs(170));
                                                println!("\n==============================");
                                                println!("   KODE PAIRING:  {}", st.pretty());
                                                println!("==============================");
                                                println!("Di HP: WhatsApp > Perangkat tertaut > Tautkan perangkat");
                                                println!("> Tautkan dengan nomor telepon > masukkan kode di atas\n");
                                            }
                                        }
                                    } else if node.child("pair-success").is_some() {
                                        let (reply, jid) = pairing::handle_pair_success(&node, creds)?;
                                        send_node(&mut tx, &mut noise, &reply).await?;
                                        creds.save(CREDS_PATH)?;
                                        println!("[+] PAIRING BERHASIL sebagai {jid}, kredensial disimpan");
                                        paired_at = Some(Instant::now());
                                    } else if node.attr("type") == Some("get") && node.child("ping").is_some() {
                                        send_node(&mut tx, &mut noise, &Node::new(
                                            "iq",
                                            &[("to", "s.whatsapp.net"), ("type", "result"), ("id", node.attr("id").unwrap_or(""))],
                                            Content::None,
                                        )).await?;
                                    } else if node.attr("type") == Some("result") && node.child("count").is_some() {
                                        let n: u32 = node
                                            .child("count")
                                            .and_then(|c| c.attr("value"))
                                            .and_then(|v| v.parse().ok())
                                            .unwrap_or(0);
                                        println!("[i] prekey di server: {n}");
                                        if n < MIN_PREKEYS {
                                            upload_prekeys(&mut tx, &mut noise, creds, store).await?;
                                        }
                                    } else if node.attr("type") == Some("error") {
                                        if registered {
                                            println!("[!] server membalas error pada iq (lihat WA_DEBUG=1 untuk detail)");
                                        } else {
                                            bail!("server mengembalikan error (lihat node di atas)");
                                        }
                                    }
                                }
                                "notification" => {
                                    if node.attr("type") == Some("link_code_companion_reg") {
                                        if let (Some(st), Some(reg)) = (&pairing, node.child("link_code_companion_reg")) {
                                            if reg.attr("stage") == Some("primary_hello") {
                                                id_n += 1;
                                                let fin = pairing::companion_finish(st, creds, reg, &format!("wars.{id_n}"))?;
                                                send_node(&mut tx, &mut noise, &fin).await?;
                                                creds.save(CREDS_PATH)?;
                                                println!("[>] kunci pairing terkirim, menunggu pair-success");
                                            }
                                        }
                                    } else if node.attr("type") == Some("encrypt") && registered {
                                        if let Some(c) = node.child("count") {
                                            let n: u32 = c.attr("value").and_then(|v| v.parse().ok()).unwrap_or(0);
                                            if n < MIN_PREKEYS {
                                                upload_prekeys(&mut tx, &mut noise, creds, store).await?;
                                            }
                                        }
                                    }
                                    send_node(&mut tx, &mut noise, &ack_for(&node)).await?;
                                }
                                "message" => {
                                    if registered {
                                        on_message(&mut tx, &mut noise, creds, store, &node).await?;
                                    }
                                }
                                "receipt" | "call" => {
                                    send_node(&mut tx, &mut noise, &ack_for(&node)).await?;
                                }
                                "success" => {
                                    if registered {
                                        logged_in = true;
                                        last_ping = Instant::now();
                                        println!("[+] LOGIN BERHASIL, bot online");
                                        send_node(&mut tx, &mut noise, &iq("wars.cnt", "get", "encrypt", vec![Node::new("count", &[], Content::None)])).await?;
                                        send_node(&mut tx, &mut noise, &iq("wars.act", "set", "passive", vec![Node::new("active", &[], Content::None)])).await?;
                                    }
                                }
                                "stream:error" => {
                                    let code = node.attr("code").unwrap_or("");
                                    if paired_at.is_some() || code == "515" {
                                        println!("[i] server minta restart (normal)");
                                        return Ok(Exit::Restart);
                                    } else if code == "401" {
                                        println!("[!] perangkat ter-logout dari WhatsApp. Hapus folder auth/ lalu pairing ulang.");
                                        return Ok(Exit::Stop);
                                    } else {
                                        bail!("stream error dari server (code={code})");
                                    }
                                }
                                "failure" => {
                                    let reason = node.attr("reason").unwrap_or("?");
                                    if reason == "401" || reason == "403" || reason == "406" {
                                        println!("[!] login ditolak (reason={reason}). Hapus folder auth/ lalu pairing ulang.");
                                        return Ok(Exit::Stop);
                                    }
                                    bail!("login gagal (reason={reason})");
                                }
                                _ => {}
                            }
                        }
                    }
                    Message::Close(c) => {
                        if paired_at.is_some() {
                            return Ok(Exit::Restart);
                        }
                        bail!("server menutup koneksi: {:?}", c);
                    }
                    _ => {}
                }
            }
            _ = ticker.tick() => {
                if !handshake_done {
                    if t1.elapsed() > Duration::from_secs(20) {
                        bail!("timeout handshake");
                    }
                } else if registered {
                    if logged_in && last_ping.elapsed() >= Duration::from_secs(25) {
                        ping_n += 1;
                        let ping = iq(&format!("wars.p{ping_n}"), "get", "w:p", vec![Node::new("ping", &[], Content::None)]);
                        send_node(&mut tx, &mut noise, &ping).await?;
                        last_ping = Instant::now();
                    }
                } else if let Some(t) = paired_at {
                    if t.elapsed() > Duration::from_secs(5) {
                        return Ok(Exit::Restart);
                    }
                } else if let Some(d) = code_deadline {
                    if Instant::now() >= d {
                        bail!("kode pairing kedaluwarsa, jalankan ulang");
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    println!("== wa-rs | Fase 4+5 | Rust native ==");

    let mut creds = creds::load_or_create(CREDS_PATH)?;
    let mut store = Store::load(SIGNAL_PATH)?;
    let phone = if creds.registered { None } else { ask_phone()? };
    let ver = wa_version();
    println!("[i] versi WA Web: {}.{}.{}", ver[0], ver[1], ver[2]);
    if let Some(j) = &creds.me_jid {
        println!("[i] akun: {j}");
    }

    let mut backoff = 2u64;
    loop {
        let res = tokio::select! {
            r = run_session(&mut creds, &mut store, phone.as_deref(), ver) => r,
            _ = tokio::signal::ctrl_c() => {
                println!("\n[i] dihentikan (Ctrl+C)");
                return Ok(());
            }
        };
        match res {
            Ok(Exit::Restart) => {
                println!("[i] menyambung ulang...");
                backoff = 2;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(Exit::Stop) => break,
            Err(e) => {
                eprintln!("[!] sesi berakhir: {e:#}");
                if !creds.registered {
                    return Err(e);
                }
                println!("[i] coba lagi dalam {backoff} detik");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }
    Ok(())
}
