//! 国际版活动 UMID 协议，移植自 cpa-workbuddy-plugin@806c61f/qoder-ai。
//!
//! MIT License
//! Copyright (c) 2026 Sliverkiss (based on workbuddy by lovingfish)
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::{write::ZlibEncoder, Compression};
use rand::RngCore;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Write;
use uuid::Uuid;

// 固定协议参数，与用户 AT、RT 及账号加密密钥无关。
const AES_KEYS: [[u8; 16]; 10] = [
    *b"IzylUK0F>mL8*8r*",
    *b"ujqho:Z>2}C)iRFU",
    *b"<pRXG;$Ms<<HTG#M",
    *b".GB$p)XY55_MuO~)",
    *b"tiq+J,!w)X@&2v9T",
    *b"LEdK.tSx]saZb!ji",
    *b"po?+,<BS$<=4JuG=",
    *b"tQEk}L*=^fOV9YS3",
    *b"8+M1me~uL$8ciY($",
    *b":H(I+$+,4@AqZg0+",
];
const BLOCK_1A: [u8; 20] = [
    0x97, 0x6f, 0x65, 0x30, 0x46, 0x3a, 0xbf, 0x1c, 0xae, 0x10, 0x52, 0x87, 0xd3, 0x85, 0x24, 0xce,
    0x60, 0xcf, 0x9f, 0xea,
];
const BLOCK_1C: [u8; 20] = [
    0x37, 0xb6, 0xa3, 0x6e, 0x52, 0xcb, 0x51, 0x37, 0xa9, 0x65, 0x2a, 0xd9, 0x56, 0xd0, 0x56, 0xaf,
    0xe8, 0x6b, 0x47, 0xdd,
];
const BLOCK_1D: [u8; 16] = [
    0x55, 0x53, 0x47, 0xdd, 0xeb, 0x68, 0x6b, 0xa6, 0x52, 0xca, 0x51, 0x37, 0x61, 0x6d, 0x29, 0xda,
];
const BLOCK_1B_WORDS: [u32; 4] = [0x12997b2f, 0x894cbd97, 0xc4a65ecb, 0xe2532f65];

pub(super) struct RequestPacket {
    pub body: String,
    pub hostname: String,
}

fn encode_block_1b(block: &[u8]) -> [u8; 16] {
    let words: [u32; 4] =
        std::array::from_fn(|i| u32::from_le_bytes(std::array::from_fn(|j| block[i * 4 + j])));
    let combined: [u32; 4] = std::array::from_fn(|i| (words[i] << 17) | (words[(i + 2) % 4] >> 15));
    let mut out = [0; 16];
    for i in 0..4 {
        out[i * 4..i * 4 + 4]
            .copy_from_slice(&(combined[(i + 1) % 4] ^ BLOCK_1B_WORDS[i]).to_le_bytes());
    }
    out
}

fn build_section_1b(sum: &[u8; 32], now_ms: i64) -> (Vec<u8>, String) {
    let hex: String = sum.iter().map(|byte| format!("{:02x}", byte)).collect();
    let mac1 = format!("00163e{}", &hex[..6]);
    let mac2 = format!("00163e{}", &hex[6..12]);
    let mac3 = format!("00163e{}", &hex[12..18]);
    let hostname = format!("qoder-{}", &hex[18..26]);
    let total = 4_096_000 + i64::from(u16::from_be_bytes([sum[13], sum[14]])) * 32;
    let free = 1_200_000 + i64::from(u16::from_be_bytes([sum[15], sum[16]])) * 16;
    let memory = format!(
        "MemTotal:        {} kB\nMemFree:         {} kB\nMemAvailable:    {} kB\nBuffers:           66568 kB\nCached:          1752368 kB\n",
        total, free, free + 1_500_000,
    );
    let kernel = format!(
        "Linux version 6.18.40.1-standard (root@{}) (gcc (GCC) 13.2.0) #1 SMP PREEMPT_DYNAMIC",
        &hex[26..38],
    );
    let machine = format!("00000000-0000-0000-0000-{}", mac1);
    let interfaces = format!("{}    {}    {}    ", mac1, mac2, mac3);
    let timestamp = now_ms.to_string();
    let fields = [
        "1000",
        timestamp.as_str(),
        "0",
        "1",
        "4",
        "1.5.0",
        "Linux",
        kernel.as_str(),
        "runtime-info-linux",
        "",
        "",
        &mac1,
        &mac1,
        "",
        &mac1[..8],
        &mac1,
        "",
        "",
        "",
        &hostname,
        "",
        "",
        &machine,
        &machine,
        "",
        "",
        "",
        "",
        &memory,
        "",
        "",
        "",
        &interfaces,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ];
    let mut serialized = Vec::new();
    for field in fields {
        serialized.extend_from_slice(&(field.len() as u16).to_be_bytes());
        serialized.extend_from_slice(field.as_bytes());
    }
    let padding = 16 - serialized.len() % 16;
    serialized.resize(serialized.len() + padding, padding as u8);
    let encoded = serialized
        .chunks_exact(16)
        .flat_map(encode_block_1b)
        .collect();
    (encoded, hostname)
}

fn wrap_section(tag: u8, blocks: &[u8], mask: &[u8]) -> Vec<u8> {
    let size = blocks.len() + 11;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&[0xcf, 0xcd]);
    out.extend_from_slice(&(size as u32).to_be_bytes());
    out.push(tag);
    out.extend_from_slice(&mask[..4]);
    out.extend(
        blocks
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ mask[(i + 2) & 3]),
    );
    out
}

pub(super) fn build_request(seed: &str, now_ms: i64) -> Result<RequestPacket, String> {
    let sum: [u8; 32] = Sha256::digest(format!("qoder-umid-{}", seed).as_bytes()).into();
    let (block_1b, hostname) = build_section_1b(&sum, now_ms);
    let sections = [
        wrap_section(0x1a, &BLOCK_1A, &sum[..4]),
        wrap_section(0x1b, &block_1b, &sum[4..8]),
        wrap_section(0x1c, &BLOCK_1C, &sum[8..12]),
        wrap_section(0x1d, &BLOCK_1D, &sum[12..16]),
    ]
    .concat();
    let mut mask = [0; 4];
    rand::rngs::OsRng
        .try_fill_bytes(&mut mask)
        .map_err(|_| "无法生成 Qoder UMID 请求随机掩码".to_string())?;
    let mut plain = Vec::with_capacity(sections.len() + 12);
    plain.extend_from_slice(&[0xcf, 0xcd, 0x00, 0x2b]);
    plain.extend_from_slice(&mask);
    plain.extend_from_slice(&((sections.len() + 12) as u32).to_be_bytes());
    plain.extend(
        sections
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ mask[i & 3]),
    );
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&plain)
        .map_err(|_| "压缩 Qoder UMID 请求失败".to_string())?;
    let mut buffer = encoder
        .finish()
        .map_err(|_| "压缩 Qoder UMID 请求失败".to_string())?;
    let length = buffer.len();
    buffer.resize(length + 16 - length % 16, 0);
    let key_index = 7;
    let key = &AES_KEYS[key_index];
    let ciphertext = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, key)
        .map_err(|_| "初始化 Qoder UMID 加密失败".to_string())?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, length)
        .map_err(|_| "加密 Qoder UMID 请求失败".to_string())?;
    let mut payload = Vec::with_capacity(ciphertext.len() + 1);
    payload.push(key_index as u8 + 1);
    payload.extend_from_slice(ciphertext);
    Ok(RequestPacket {
        body: STANDARD.encode(payload),
        hostname,
    })
}

pub(super) fn decrypt_response(encoded: &str) -> Result<String, String> {
    let mut payload = STANDARD
        .decode(encoded)
        .map_err(|_| "Qoder UMID 响应不是有效的 Base64".to_string())?;
    let key = payload
        .first()
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| AES_KEYS.get(index as usize))
        .ok_or("Qoder UMID 响应密钥索引无效")?;
    if payload.len() < 17 || (payload.len() - 1) % 16 != 0 {
        return Err("Qoder UMID 响应密文长度无效".into());
    }
    let plain = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, key)
        .map_err(|_| "初始化 Qoder UMID 解密失败".to_string())?
        .decrypt_padded_mut::<Pkcs7>(&mut payload[1..])
        .map_err(|_| "Qoder UMID 响应解密失败".to_string())?;
    #[derive(Deserialize)]
    struct Response {
        eeid: String,
    }
    let token = serde_json::from_slice::<Response>(plain)
        .map_err(|_| "Qoder UMID 响应缺少有效的 eeid".to_string())?
        .eeid;
    if token.is_empty()
        || token.len() > 8192
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err("Qoder UMID 返回的设备令牌无效".into());
    }
    Ok(token)
}

pub(super) fn machine_id(seed: &str) -> String {
    let mut hash = Sha1::new();
    hash.update(Uuid::NAMESPACE_DNS.as_bytes());
    hash.update(seed.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

pub(super) fn derive_codes(token: &str, vm_code: u8, percentage: u8) -> (String, String) {
    let token_hash = format!("{:016x}", xxh64(token.as_bytes()));
    let kind = format!("{}{:02}{}", &token_hash[..8], vm_code, &token_hash[8..]);
    let corrected_percentage = if percentage >= 51 {
        percentage - 1
    } else {
        percentage
    };
    let kind_hash = format!("{:016x}", xxh64(kind.as_bytes()));
    let code = format!(
        "{}{:02}{}",
        &kind_hash[..8],
        corrected_percentage,
        &kind_hash[8..]
    );
    (kind, code)
}

fn xxh64(data: &[u8]) -> u64 {
    const P1: u64 = 11400714785074694791;
    const P2: u64 = 14029467366897019727;
    const P3: u64 = 1609587929392839161;
    const P4: u64 = 9650029242287828579;
    const P5: u64 = 2870177450012600261;
    let round = |value: u64, lane: u64| {
        value
            .wrapping_add(lane.wrapping_mul(P2))
            .rotate_left(31)
            .wrapping_mul(P1)
    };
    let read_u64 = |offset: usize| u64::from_le_bytes(std::array::from_fn(|i| data[offset + i]));
    let mut offset = 0;
    let mut hash = if data.len() >= 32 {
        let mut lanes = [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)];
        while offset + 32 <= data.len() {
            for (i, lane) in lanes.iter_mut().enumerate() {
                *lane = round(*lane, read_u64(offset + i * 8));
            }
            offset += 32;
        }
        let mut hash = lanes[0]
            .rotate_left(1)
            .wrapping_add(lanes[1].rotate_left(7))
            .wrapping_add(lanes[2].rotate_left(12))
            .wrapping_add(lanes[3].rotate_left(18));
        for lane in lanes {
            hash = (hash ^ round(0, lane)).wrapping_mul(P1).wrapping_add(P4);
        }
        hash
    } else {
        P5
    };
    hash = hash.wrapping_add(data.len() as u64);
    while offset + 8 <= data.len() {
        hash = (hash ^ round(0, read_u64(offset)))
            .rotate_left(27)
            .wrapping_mul(P1)
            .wrapping_add(P4);
        offset += 8;
    }
    if offset + 4 <= data.len() {
        let lane = u32::from_le_bytes(std::array::from_fn(|i| data[offset + i]));
        hash = (hash ^ u64::from(lane).wrapping_mul(P1))
            .rotate_left(23)
            .wrapping_mul(P2)
            .wrapping_add(P3);
        offset += 4;
    }
    for byte in &data[offset..] {
        hash = (hash ^ u64::from(*byte).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(P3);
    hash ^ (hash >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_xxh64_vectors_cover_short_and_lane_paths() {
        assert_eq!(xxh64(b""), 0xef46db3751d8e999);
        assert_eq!(xxh64(b"a"), 0xd24ec4f1a98c6e5b);
        assert_eq!(xxh64(b"abc"), 0x44bc2cf5ad770999);
        assert_eq!(xxh64(b"abcdefghijklmnopqrstuvwxyz"), 0xcfe1f278fa89835c);
        assert_eq!(
            xxh64(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            0xaaa46907d3047814
        );
    }

    #[test]
    fn account_seed_controls_machine_identity_and_hostname() {
        let first = build_request("fixture-user-a#0", 1_790_000_000_000).unwrap();
        let same = build_request("fixture-user-a#0", 1_790_000_000_100).unwrap();
        let other = build_request("fixture-user-b#0", 1_790_000_000_000).unwrap();
        assert_eq!(first.hostname, same.hostname);
        assert_ne!(first.hostname, other.hostname);
        assert_ne!(
            machine_id("fixture-user-a#0"),
            machine_id("fixture-user-b#0")
        );
        assert_eq!(
            machine_id("www.example.com"),
            "2ed6657d-e927-568b-95e1-2665a8aea6a2"
        );
        let payload = STANDARD.decode(first.body).unwrap();
        assert_eq!(payload[0], 8);
        assert_eq!((payload.len() - 1) % 16, 0);
    }

    #[test]
    fn request_encodes_the_reference_outer_envelope_and_four_sections() {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let packet = build_request("fixture-user#0", 1_790_000_000_000).unwrap();
        let mut payload = STANDARD.decode(packet.body).unwrap();
        let compressed = cbc::Decryptor::<aes::Aes128>::new_from_slices(&AES_KEYS[7], &AES_KEYS[7])
            .unwrap()
            .decrypt_padded_mut::<Pkcs7>(&mut payload[1..])
            .unwrap();
        let mut plain = Vec::new();
        ZlibDecoder::new(compressed)
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(&plain[..4], &[0xcf, 0xcd, 0, 0x2b]);
        assert_eq!(
            u32::from_be_bytes(plain[8..12].try_into().unwrap()) as usize,
            plain.len()
        );
        let sections: Vec<u8> = plain[12..]
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ plain[4 + (i & 3)])
            .collect();
        let mut offset = 0;
        let mut tags = Vec::new();
        while offset < sections.len() {
            assert_eq!(&sections[offset..offset + 2], &[0xcf, 0xcd]);
            let size =
                u32::from_be_bytes(sections[offset + 2..offset + 6].try_into().unwrap()) as usize;
            let tag = sections[offset + 6];
            let data: Vec<u8> = sections[offset + 11..offset + size]
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ sections[offset + 7 + ((i + 2) & 3)])
                .collect();
            match tag {
                0x1a => assert_eq!(data.len(), 20),
                0x1b => {
                    // 用参考实现原函数为相同虚构种子和固定时间生成的报文摘要，
                    // 校验完整字段布局与块编码，避免遗漏空字段仍能通过外层结构检查。
                    assert_eq!(data.len(), 560);
                    assert_eq!(
                        format!("{:x}", Sha256::digest(&data)),
                        "3b20c445205b7d31933e47077a3de6e56ea0d04f4e3d96898ebd9de8d10fb102"
                    );
                }
                0x1c => assert_eq!(data.len(), 20),
                0x1d => assert_eq!(data.len(), 16),
                _ => panic!("unexpected protocol section"),
            }
            tags.push(tag);
            offset += size;
        }
        assert_eq!(tags, [0x1a, 0x1b, 0x1c, 0x1d]);
    }

    #[test]
    fn response_rejects_bad_index_length_and_padding() {
        for value in [
            "!invalid!".to_string(),
            STANDARD.encode([0; 17]),
            STANDARD.encode([11; 17]),
            STANDARD.encode([1; 16]),
            STANDARD.encode([1; 17]),
        ] {
            assert!(decrypt_response(&value).is_err());
        }
    }
}
