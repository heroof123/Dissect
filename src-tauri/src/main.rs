#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::Serialize;
use std::path::PathBuf;
use tauri::Emitter;

// ── Types ─────────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct GpuInfo {
    name: String,
    driver: String,
    vram_mb: u64,
    cuda: bool,
    compute_cap: String,
}

#[derive(Serialize)]
struct SystemInfo {
    cpu: String,
    cores: usize,
    ram_gb: f64,
    os: String,
    gpus: Vec<GpuInfo>,
}

#[derive(Serialize)]
struct ModelFile {
    name: String,
    path: String,
    size_mb: f64,
}

// ── Commands ──────────────────────────────────────────────────────────

#[tauri::command]
fn get_system_info() -> SystemInfo {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu   = sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_else(|| "Unknown CPU".into());
    let cores = sys.cpus().len();
    let ram_gb = sys.total_memory() as f64 / 1_073_741_824.0;
    let os    = System::long_os_version().unwrap_or_default();

    SystemInfo { cpu, cores, ram_gb, os, gpus: detect_gpus() }
}

fn detect_gpus() -> Vec<GpuInfo> {
    // NVIDIA — nvidia-smi
    if let Ok(out) = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,driver_version,memory.total,compute_cap", "--format=csv,noheader,nounits"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let gpus: Vec<GpuInfo> = text.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|line| {
                    let p: Vec<&str> = line.split(',').map(str::trim).collect();
                    GpuInfo {
                        name:        p.first().unwrap_or(&"NVIDIA GPU").to_string(),
                        driver:      p.get(1).unwrap_or(&"").to_string(),
                        vram_mb:     p.get(2).and_then(|s| s.parse().ok()).unwrap_or(0),
                        cuda:        true,
                        compute_cap: p.get(3).unwrap_or(&"").to_string(),
                    }
                })
                .collect();
            if !gpus.is_empty() { return gpus; }
        }
    }

    // Fallback — WMIC (AMD / Intel / generic)
    if let Ok(out) = std::process::Command::new("wmic")
        .args(["path", "win32_videocontroller", "get", "name,adapterram", "/format:csv"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        let gpus: Vec<GpuInfo> = text.lines()
            .skip(2)
            .filter(|l| l.contains(','))
            .filter_map(|line| {
                let p: Vec<&str> = line.splitn(3, ',').collect();
                let name = p.get(2)?.trim().to_string();
                if name.is_empty() { return None; }
                let vram_mb = p.get(1)
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0) / 1_048_576;
                Some(GpuInfo { name, driver: String::new(), vram_mb, cuda: false, compute_cap: String::new() })
            })
            .collect();
        if !gpus.is_empty() { return gpus; }
    }

    vec![]
}

#[tauri::command]
fn list_models(dir: String) -> Vec<ModelFile> {
    let path = PathBuf::from(&dir);
    if !path.exists() { return vec![]; }

    std::fs::read_dir(&path)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let ext = p.extension()?.to_str()?;
            if !["gguf", "bin"].contains(&ext) { return None; }
            let size_mb = e.metadata().map(|m| m.len() as f64 / 1_048_576.0).unwrap_or(0.0);
            Some(ModelFile {
                name:     p.file_name()?.to_string_lossy().to_string(),
                path:     p.to_string_lossy().to_string(),
                size_mb,
            })
        })
        .collect()
}

#[tauri::command]
async fn download_model(
    url:  String,
    dest: String,
    app:  tauri::AppHandle,
) -> Result<(), String> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = PathBuf::from(&dest).parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
    }

    let client = reqwest::Client::builder()
        .user_agent("LegacyPatch-Studio/2.0")
        .build()
        .map_err(|e| e.to_string())?;

    let res = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("HTTP {} — {}", res.status(), url));
    }

    let total       = res.content_length().unwrap_or(0);
    let mut done    = 0u64;
    let mut file    = tokio::fs::File::create(&dest).await.map_err(|e| e.to_string())?;
    let mut stream  = res.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| e.to_string())?;
        file.write_all(&bytes).await.map_err(|e| e.to_string())?;
        done += bytes.len() as u64;
        if total > 0 {
            let _ = app.emit("dl-progress", serde_json::json!({
                "pct":      (done as f64 / total as f64 * 100.0) as u8,
                "mb":       done as f64 / 1_048_576.0,
                "total_mb": total as f64 / 1_048_576.0,
            }));
        }
    }

    file.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Sends PE scan JSON to a local Ollama instance — streams tokens via `ai-chunk` / `ai-done`.
#[tauri::command]
async fn ai_analyze(
    pe_json:  String,
    model:    String,
    base_url: String,
    app:      tauri::AppHandle,
) -> Result<(), String> {
    use futures_util::StreamExt;

    let prompt = format!(
        "You are CoreXAI, a binary security researcher and reverse engineering assistant. \
         Analyze this Windows PE executable scan result and provide:\n\
         1. Summary of detected protections and mechanisms\n\
         2. Assessment of suspicious sections / entropy spikes\n\
         3. Overall risk level with reasoning\n\
         4. Key observations for a reverse engineer\n\n\
         Use markdown formatting with headings and bullet points. Be thorough.\n\n\
         PE Scan JSON:\n{}\n",
        pe_json
    );

    let client = reqwest::Client::new();
    let body   = serde_json::json!({
        "model":  model,
        "prompt": prompt,
        "stream": true,
        "options": { "num_predict": 1500, "temperature": 0.2 }
    });

    let res = client
        .post(format!("{}/api/generate", base_url.trim_end_matches('/')))
        .json(&body)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| format!("Cannot reach Ollama at {}: {}", base_url, e))?;

    if !res.status().is_success() {
        return Err(format!("Ollama returned HTTP {}", res.status()));
    }

    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| e.to_string())?;
        let text  = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(token) = obj["response"].as_str() {
                    if !token.is_empty() { let _ = app.emit("ai-chunk", token.to_string()); }
                }
                if obj["done"].as_bool().unwrap_or(false) {
                    let _ = app.emit("ai-done", ());
                    return Ok(());
                }
            }
        }
    }
    let _ = app.emit("ai-done", ());
    Ok(())
}

// ── Hex Patcher (42 + 43) ─────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct PatchInput {
    name:    String,
    offset:  String,
    patched: String,
    enabled: bool,
}

#[tauri::command]
fn apply_patches(file_path: String, patches: Vec<PatchInput>) -> Result<String, String> {
    use std::io::{Seek, SeekFrom, Write};

    let enabled: Vec<&PatchInput> = patches.iter().filter(|p| p.enabled).collect();
    if enabled.is_empty() { return Err("Aktif patch yok".into()); }

    // 43 — Backup
    let backup_path = format!("{}.bak", file_path);
    std::fs::copy(&file_path, &backup_path)
        .map_err(|e| format!("Backup oluşturulamadı: {}", e))?;

    let mut file = std::fs::OpenOptions::new()
        .read(true).write(true).open(&file_path)
        .map_err(|e| format!("Dosya açılamadı: {}", e))?;

    let mut applied = 0usize;
    for p in &enabled {
        let offset = if p.offset.to_lowercase().starts_with("0x") {
            u64::from_str_radix(&p.offset[2..], 16)
                .map_err(|_| format!("Geçersiz offset: {}", p.name))?
        } else {
            p.offset.parse::<u64>().map_err(|_| format!("Geçersiz offset: {}", p.name))?
        };

        let bytes: Vec<u8> = p.patched.split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();
        if bytes.is_empty() { continue; }

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek hatası ({}): {}", p.name, e))?;
        file.write_all(&bytes)
            .map_err(|e| format!("Yazma hatası ({}): {}", p.name, e))?;
        applied += 1;
    }

    // 59 — Rewrite checksum after patches
    drop(file);
    let mut data = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    recalc_pe_checksum(&mut data);
    std::fs::write(&file_path, &data).map_err(|e| e.to_string())?;

    Ok(format!("{} patch uygulandı, checksum güncellendi. Yedek: {}", applied, backup_path))
}

/// Recalculate and write PE checksum (59)
fn recalc_pe_checksum(data: &mut Vec<u8>) {
    if data.len() < 0x40 { return; }
    let pe_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_off + 24 + 68 > data.len() { return; }
    // Zero out existing checksum field before computing
    let cksum_off = pe_off + 24 + 64;
    data[cksum_off]     = 0;
    data[cksum_off + 1] = 0;
    data[cksum_off + 2] = 0;
    data[cksum_off + 3] = 0;
    // Compute checksum (Microsoft algorithm)
    let mut sum: u64 = 0;
    let words = data.len() / 2;
    for i in 0..words {
        let w = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]) as u64;
        sum = (sum & 0xFFFF) + w + (sum >> 16);
        if sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
    }
    let checksum = ((sum & 0xFFFF) + (data.len() as u64)) as u32;
    let cb = checksum.to_le_bytes();
    data[cksum_off]     = cb[0];
    data[cksum_off + 1] = cb[1];
    data[cksum_off + 2] = cb[2];
    data[cksum_off + 3] = cb[3];
}

// ── Hex Region Reader (44) ────────────────────────────────────────────

#[tauri::command]
fn read_hex_region(file_path: String, offset: u64, length: usize) -> Result<String, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(&file_path)
        .map_err(|e| format!("Dosya açılamadı: {}", e))?;
    let file_len  = file.metadata().map_err(|e| e.to_string())?.len();
    let real_off  = offset.min(file_len.saturating_sub(1));
    let read_len  = length.min((file_len - real_off) as usize).min(256);

    file.seek(SeekFrom::Start(real_off)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf).map_err(|e| e.to_string())?;

    let hex_str = buf.iter().enumerate()
        .map(|(i, b)| {
            let sep = if i > 0 && i % 16 == 0 { "\n" } else if i > 0 && i % 8 == 0 { "  " } else if i > 0 { " " } else { "" };
            format!("{}{:02X}", sep, b)
        })
        .collect::<String>();

    Ok(hex_str)
}

// ── PE Rust Parser using goblin (55) ─────────────────────────────────

fn calc_entropy_rs(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len; acc - p * p.log2()
    })
}

#[tauri::command]
fn parse_pe_rust(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;

    match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => {
            let sections: Vec<serde_json::Value> = pe.sections.iter().map(|s| {
                let name    = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
                let off     = s.pointer_to_raw_data as usize;
                let sz      = s.size_of_raw_data as usize;
                let entropy = if sz > 0 && off + sz <= data.len() {
                    calc_entropy_rs(&data[off..(off + sz).min(data.len())])
                } else { 0.0 };
                serde_json::json!({
                    "name":       name,
                    "vaddr":      format!("0x{:08X}", s.virtual_address),
                    "vsize":      s.virtual_size,
                    "rsize":      s.size_of_raw_data,
                    "entropy":    (entropy * 1000.0).round() / 1000.0,
                    "executable": (s.characteristics & 0x2000_0000) != 0,
                    "writable":   (s.characteristics & 0x8000_0000) != 0,
                })
            }).collect();

            // Group imports by DLL
            let mut dll_map: std::collections::BTreeMap<String, Vec<String>> = Default::default();
            for imp in &pe.imports {
                dll_map.entry(imp.dll.to_lowercase()).or_default().push(imp.name.to_string());
            }
            let imports: Vec<serde_json::Value> = dll_map.into_iter().map(|(dll, funcs)| {
                serde_json::json!({ "dll": dll, "funcs": funcs })
            }).collect();

            // B2 — TLS: presence of .tls section
            let has_tls: bool = pe.sections.iter()
                .any(|s| s.name.starts_with(b".tls") || s.name.starts_with(b"TLS"));

            // B3 — Exception: .pdata section → each RUNTIME_FUNCTION is 12 bytes
            let exception_entries: usize = pe.sections.iter()
                .find(|s| s.name.starts_with(b".pdata"))
                .map(|s| (s.size_of_raw_data as usize) / 12)
                .unwrap_or(0);

            // B8 — Debug/PDB: scan for "RSDS" signature in binary
            let debug_pdb: String = {
                const RSDS: &[u8] = b"RSDS";
                data.windows(4).position(|w| w == RSDS).and_then(|pos| {
                    let start = pos + 24; // skip signature(4) + GUID(16) + age(4)
                    if start >= data.len() { return None; }
                    let rest = &data[start..];
                    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len().min(260));
                    let s = String::from_utf8_lossy(&rest[..end]).to_string();
                    if s.ends_with(".pdb") || s.contains('\\') || s.contains('/') { Some(s) } else { None }
                }).unwrap_or_default()
            };

            // B4 — Delayed imports: check pe.libraries for delay-load marker
            // goblin 0.7 doesn't expose them directly; detect via import naming convention
            let delayed_imports: Vec<String> = pe.imports.iter()
                .filter(|i| i.name == "__delayLoadHelper2" || i.dll.to_lowercase().contains("delayimp"))
                .map(|i| i.dll.to_string())
                .collect();

            Ok(serde_json::json!({
                "arch":        if pe.is_64 { "PE32+" } else { "PE32" },
                "entry_point": format!("0x{:08X}", pe.entry),
                "image_base":  format!("0x{:08X}", pe.image_base),
                "is_dll":      (pe.header.coff_header.characteristics & 0x2000) != 0,
                "num_sections": sections.len(),
                "sections":    sections,
                "imports":     imports,
                // B4 — Delayed imports
                "delayed_imports": delayed_imports,
                // B8 — Debug directory (PDB path)
                "debug_pdb":   debug_pdb,
                // B2 — TLS section detected
                "has_tls":     has_tls,
                // B3 — Exception directory size
                "exception_entries": exception_entries,
            }))
        }
        _ => Err("PE binary değil".into()),
    }
}

// ── File Hash SHA-256 (56) ────────────────────────────────────────────

#[tauri::command]
fn file_hash(file_path: String) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(format!("{:x}", h.finalize()))
}

// ── Multi-Hash: MD5 + SHA1 + SHA256 + CRC32 (F5) ─────────────────────

#[tauri::command]
fn multi_hash(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;

    use sha2::Digest as _;
    let sha256 = format!("{:x}", sha2::Sha256::digest(&data));
    let sha1   = format!("{:x}", sha1::Sha1::digest(&data));
    let md5v   = format!("{:x}", md5::Md5::digest(&data));

    // CRC32 (inline — no extra crate)
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in &data {
        crc ^= b as u32;
        for _ in 0..8 { crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 }; }
    }
    let crc32 = format!("{:08X}", crc ^ 0xFFFF_FFFF);

    Ok(serde_json::json!({ "md5": md5v, "sha1": sha1, "sha256": sha256, "crc32": crc32 }))
}

// ── LM Studio ─────────────────────────────────────────────────────

#[tauri::command]
async fn lms_list_models(base_url: String, api_key: String) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client
        .get(format!("{}/v1/models", base_url.trim_end_matches('/')));
    if !api_key.trim().is_empty() {
        req = req.header("Authorization", format!("Bearer {}", api_key.trim()));
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("LM Studio'ya ulaşılamıyor ({}): {}", base_url, e))?;
    if !res.status().is_success() {
        return Err(format!("HTTP {} — API key gerekiyor olabilir", res.status()));
    }
    let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    Ok(json["data"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|m| m["id"].as_str().map(String::from))
        .collect())
}

#[tauri::command]
async fn lms_chat_stream(
    messages: Vec<serde_json::Value>,
    model:    String,
    base_url: String,
    api_key:  String,
    app:      tauri::AppHandle,
) -> Result<(), String> {
    use futures_util::StreamExt;
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "model": model,
        "messages": messages,
        "stream": true,
        "temperature": 0.7,
        "max_tokens": 2048,
    });
    let mut req = client
        .post(format!("{}/v1/chat/completions", base_url.trim_end_matches('/')))
        .json(&body)
        .timeout(std::time::Duration::from_secs(300));
    if !api_key.trim().is_empty() {
        req = req.header("Authorization", format!("Bearer {}", api_key.trim()));
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("LM Studio'ya ulaşılamıyor: {}", e))?;
    if !res.status().is_success() {
        return Err(format!(
            "HTTP {} — API key yanlış veya model yüklü değil",
            res.status()
        ));
    }
    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if data.trim() == "[DONE]" {
                    let _ = app.emit("chat-done", ());
                    return Ok(());
                }
                if let Ok(obj) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(content) = obj["choices"][0]["delta"]["content"].as_str() {
                        if !content.is_empty() {
                            let _ = app.emit("chat-chunk", content.to_string());
                        }
                    }
                }
            }
        }
    }
    let _ = app.emit("chat-done", ());
    Ok(())
}

#[tauri::command]
fn get_cuda_version() -> Option<String> {
    // nvcc gives the exact toolkit version
    if let Ok(out) = std::process::Command::new("nvcc").args(["--version"]).output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = text.lines().find(|l| l.contains("release")) {
                return Some(line.trim().to_string());
            }
        }
    }
    // Fallback: nvidia-smi shows driver-side CUDA version
    if let Ok(out) = std::process::Command::new("nvidia-smi").output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = text.lines().find(|l| l.contains("CUDA Version")) {
                if let Some(ver) = line.split("CUDA Version:").nth(1) {
                    let v = ver.trim().split_whitespace().next().unwrap_or("?");
                    return Some(format!("CUDA {} (driver)", v));
                }
            }
        }
    }
    None
}

// ── GGUF Direct: spawn llama-server ──────────────────────────────────

#[tauri::command]
fn start_gguf_server(gguf_path: String, port: u16) -> Result<String, String> {
    // Try common llama.cpp binaries in PATH
    let binaries = ["llama-server", "llama-server.exe", "server", "llama.cpp"];
    let mut found = None;
    for b in &binaries {
        if std::process::Command::new(b).arg("--version").output().is_ok() {
            found = Some(*b);
            break;
        }
    }
    let bin = found.ok_or_else(|| {
        "llama-server PATH'te bulunamadı. llama.cpp kurun: https://github.com/ggeronim/llama.cpp/releases".to_string()
    })?;
    std::process::Command::new(bin)
        .args([
            "--model",    &gguf_path,
            "--port",     &port.to_string(),
            "--ctx-size", "4096",
            "--threads",  "4",
            "--host",     "127.0.0.1",
        ])
        .spawn()
        .map_err(|e| format!("Sunucu başlatılamadı: {}", e))?;
    Ok(format!("http://127.0.0.1:{}", port))
}

// ── HuggingFace GGUF search ───────────────────────────────────────────

#[tauri::command]
async fn search_hf_gguf(query: String) -> Result<serde_json::Value, String> {
    use std::io::Read;
    let url = format!(
        "https://huggingface.co/api/models?search={}&filter=gguf&limit=10&sort=likes&direction=-1",
        urlencoding_simple(&query)
    );
    let resp = ureq::get(&url)
        .set("User-Agent", "Dissect/2.0")
        .call()
        .map_err(|e| format!("HuggingFace API hatası: {}", e))?;
    let mut body = String::new();
    resp.into_reader().read_to_string(&mut body).map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(json)
}

fn urlencoding_simple(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c.to_string() } else { format!("%{:02X}", c as u32) }).collect()
}

// ── GGUF Direct: spawn llama-server ──────────────────────────────────


#[tauri::command]
fn unpack_upx(file_path: String) -> Result<serde_json::Value, String> {
    let p = std::path::Path::new(&file_path);
    if !p.exists() {
        return Err("File not found".into());
    }
    // Try to locate upx in PATH (or next to the executable)
    let out = std::process::Command::new("upx")
        .args(["--decompress", "--force", &file_path])
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
            if o.status.success() {
                Ok(serde_json::json!({ "ok": true, "msg": stdout.trim() }))
            } else {
                Ok(serde_json::json!({ "ok": false, "msg": stderr.trim().to_string() + &stdout }))
            }
        }
        Err(e) => Ok(serde_json::json!({
            "ok": false,
            "msg": format!("upx not found in PATH: {}. Install UPX and ensure it is in PATH.", e)
        })),
    }
}

// ── F3: Memory dump / raw binary analysis ────────────────────────────

#[tauri::command]
fn analyze_dump(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let size = data.len();
    // Try to find embedded PE headers (MZ signatures)
    let mut pe_offsets: Vec<u64> = Vec::new();
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == 0x4D && data[i + 1] == 0x5A {
            pe_offsets.push(i as u64);
            if pe_offsets.len() >= 20 { break; }
        }
    }
    // Entropy of full dump
    let mut freq = [0u64; 256];
    for &b in &data { freq[b as usize] += 1; }
    let n = data.len() as f64;
    let entropy: f64 = freq.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / n; -p * p.log2() }).sum();
    // Strings (ASCII ≥5 chars)
    let mut strings: Vec<String> = Vec::new();
    let mut cur = String::new();
    for &b in &data {
        if b >= 0x20 && b < 0x7f { cur.push(b as char); }
        else { if cur.len() >= 5 { strings.push(cur.clone()); } cur.clear(); }
        if strings.len() >= 500 { break; }
    }
    Ok(serde_json::json!({
        "size": size,
        "entropy": entropy,
        "pe_offsets": pe_offsets,
        "strings_sample": strings.into_iter().take(100).collect::<Vec<_>>(),
        "is_likely_dump": pe_offsets.len() > 1 || (entropy > 5.0 && entropy < 7.5),
    }))
}

// ── Disassembly — Entry Point (A1/A2) ────────────────────────────────

#[tauri::command]
fn disassemble_ep(file_path: String, count: usize) -> Result<Vec<serde_json::Value>, String> {
    use capstone::prelude::*;

    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let ep_rva      = pe.entry;
    let image_base  = pe.image_base as u64;

    // RVA → file offset
    let ep_foff = pe.sections.iter().find_map(|s| {
        let vstart = s.virtual_address as usize;
        let vend   = vstart + s.virtual_size as usize;
        if ep_rva >= vstart && ep_rva < vend {
            Some(s.pointer_to_raw_data as usize + (ep_rva - vstart))
        } else { None }
    }).ok_or_else(|| "EP section bulunamadı".to_string())?;

    let max_bytes = (count * 15).min(data.len().saturating_sub(ep_foff));
    let code      = &data[ep_foff..ep_foff + max_bytes];

    let cs = if pe.is_64 {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()
    } else {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build()
    }.map_err(|e| e.to_string())?;

    let insns = cs.disasm_count(code, image_base + ep_rva as u64, count)
        .map_err(|e| e.to_string())?;

    // A2 — basic block info: tag CALL/JMP/RET instructions
    Ok(insns.iter().map(|i| {
        let mn = i.mnemonic().unwrap_or("").to_lowercase();
        let kind = if mn.starts_with("ret") { "ret" }
            else if mn.starts_with("call") { "call" }
            else if mn.starts_with("jmp") || mn.starts_with("j") { "jmp" }
            else { "" };
        serde_json::json!({
            "addr":     format!("0x{:08X}", i.address()),
            "bytes":    i.bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
            "mnemonic": i.mnemonic().unwrap_or(""),
            "operands": i.op_str().unwrap_or(""),
            "kind":     kind,
        })
    }).collect())
}

// ── Entry ─────────────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            list_models,
            download_model,
            ai_analyze,
            lms_list_models,
            lms_chat_stream,
            get_cuda_version,
            apply_patches,
            read_hex_region,
            parse_pe_rust,
            file_hash,
            multi_hash,
            disassemble_ep,
            unpack_upx,
            analyze_dump,
            start_gguf_server,
            search_hf_gguf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

