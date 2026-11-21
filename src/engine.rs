use std::collections::HashMap;
use std::process::Command;
use anyhow::{Context, Result};
use crate::packet::{LayerItem, PacketDetail, PacketSummary};

#[derive(Debug, Clone)]
pub enum CaptureSource {
    File(String),
    Interface(String),
}

pub struct Engine {
    pub source: CaptureSource,
    pub filter: Option<String>,
    pub max_count: Option<usize>,
    pub details_cache: HashMap<usize, PacketDetail>,
}

impl Engine {
    pub fn new(source: CaptureSource, filter: Option<String>, max_count: Option<usize>) -> Self {
        Self {
            source,
            filter,
            max_count,
            details_cache: HashMap::new(),
        }
    }

    pub fn load_summaries(&self) -> Result<Vec<PacketSummary>> {
        let mut cmd = Command::new("tshark");

        match &self.source {
            CaptureSource::File(path) => {
                cmd.arg("-r").arg(path);
            }
            CaptureSource::Interface(iface) => {
                cmd.arg("-i").arg(iface);
            }
        }

        if let Some(f) = &self.filter {
            if !f.trim().is_empty() {
                cmd.arg("-Y").arg(f.trim());
            }
        }

        if let Some(count) = self.max_count {
            cmd.arg("-c").arg(count.to_string());
        }

        cmd.args([
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "_ws.col.Source",
            "-e", "_ws.col.Destination",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "_ws.col.Info",
            "-E", "separator=\t",
        ]);

        let output = cmd.output().context("Failed to execute tshark. Is tshark installed and in your PATH?")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            if err.contains("is not a valid display filter") {
                anyhow::bail!("Invalid display filter: {}", self.filter.as_deref().unwrap_or(""));
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut summaries = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.is_empty() {
                continue;
            }

            let number = parts[0].parse::<usize>().unwrap_or(summaries.len() + 1);
            let time = parts.get(1).unwrap_or(&"0.000000").to_string();
            let source = parts.get(2).unwrap_or(&"").to_string();
            let destination = parts.get(3).unwrap_or(&"").to_string();
            let protocol = parts.get(4).unwrap_or(&"").to_string();
            let length = parts.get(5).unwrap_or(&"").to_string();
            let info = parts.get(6).unwrap_or(&"").to_string();

            summaries.push(PacketSummary {
                number,
                time,
                source,
                destination,
                protocol,
                length,
                info,
            });
        }

        Ok(summaries)
    }

    pub fn get_detail(&mut self, frame_number: usize) -> Result<PacketDetail> {
        if let Some(detail) = self.details_cache.get(&frame_number) {
            return Ok(detail.clone());
        }

        let mut cmd = Command::new("tshark");
        match &self.source {
            CaptureSource::File(path) => {
                cmd.arg("-r").arg(path);
            }
            CaptureSource::Interface(iface) => {
                cmd.arg("-i").arg(iface);
            }
        }

        let filter_expr = format!("frame.number == {}", frame_number);
        cmd.arg("-Y").arg(&filter_expr).args(["-V", "-x"]);

        let output = cmd.output().context("Failed to fetch packet details from tshark")?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut layers = Vec::new();
        let mut raw_hex_lines = Vec::new();
        let mut in_hexdump = false;

        for line in stdout.lines() {
            if !in_hexdump {
                // Check if hex dump section started (e.g., "0000  00 00 ...")
                if line.starts_with("0000  ") || (line.len() >= 6 && &line[4..6] == "  " && line.chars().take(4).all(|c| c.is_ascii_hexdigit())) {
                    in_hexdump = true;
                    raw_hex_lines.push(line.to_string());
                    continue;
                }

                if line.trim().is_empty() {
                    continue;
                }

                let indent = line.len() - line.trim_start().len();
                let is_header = indent == 0;
                layers.push(LayerItem {
                    title: line.to_string(),
                    indent,
                    is_header,
                });
            } else {
                if !line.trim().is_empty() {
                    raw_hex_lines.push(line.to_string());
                }
            }
        }

        // Parse hex bytes from raw_hex_lines
        let mut raw_bytes = Vec::new();
        for line in &raw_hex_lines {
            // Format: "0000  00 00 c0 9f a0 97 00 a0 cc 3b bf fa 08 00 45 10   .........;....E."
            if line.len() > 6 {
                let content = &line[6..];
                // Split hex and ascii columns by 3 spaces
                let hex_part = if let Some(idx) = content.find("   ") {
                    &content[..idx]
                } else {
                    content
                };
                for token in hex_part.split_whitespace() {
                    if token.len() == 2 {
                        if let Ok(b) = u8::from_str_radix(token, 16) {
                            raw_bytes.push(b);
                        }
                    }
                }
            }
        }

        let detail = PacketDetail {
            layers,
            raw_bytes,
        };

        self.details_cache.insert(frame_number, detail.clone());
        Ok(detail)
    }
}
