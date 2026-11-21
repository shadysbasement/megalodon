use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub number: usize,
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: String,
    pub info: String,
}

#[derive(Debug, Clone)]
pub struct LayerItem {
    pub title: String,
    #[allow(dead_code)]
    pub indent: usize,
    pub is_header: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PacketDetail {
    pub layers: Vec<LayerItem>,
    pub raw_bytes: Vec<u8>,
}

#[allow(dead_code)]
pub fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = hex_str.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    for chunk in chars.chunks(2) {
        if chunk.len() == 2 {
            let s: String = chunk.iter().collect();
            if let Ok(b) = u8::from_str_radix(&s, 16) {
                bytes.push(b);
            }
        }
    }
    bytes
}

pub fn format_hex_dump(bytes: &[u8]) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = format!("{:04x}", i * 16);
        let mut hex_parts = Vec::new();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex_parts.push(format!(" {:02x}", b));
            } else {
                hex_parts.push(format!("{:02x}", b));
            }
        }
        let hex_str = format!("{:<49}", hex_parts.join(" "));
        let ascii_str: String = chunk
            .iter()
            .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
            .collect();
        rows.push((offset, hex_str, ascii_str));
    }
    rows
}
