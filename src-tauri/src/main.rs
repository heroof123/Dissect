#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
#![recursion_limit = "512"]

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

// ══════════════════════════════════════════════════════════════════════
// FAZ 3.1 — Full PE Scanner in Rust (replaces JS analyzePE)
// ══════════════════════════════════════════════════════════════════════

fn extract_strings_rs(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let limit = data.len().min(2 * 1024 * 1024); // first 2MB

    // ASCII strings
    let mut cur = String::new();
    for &b in &data[..limit] {
        if b >= 0x20 && b < 0x7f {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len { result.push(cur.clone()); }
            cur.clear();
        }
        if result.len() >= 1200 { break; }
    }
    if cur.len() >= min_len && result.len() < 1200 { result.push(cur); }

    // UTF-16LE strings
    if result.len() < 1200 {
        let mut u16buf = String::new();
        let mut i = 0;
        while i + 1 < limit && result.len() < 1200 {
            let ch = u16::from_le_bytes([data[i], data[i + 1]]);
            if ch >= 0x20 && ch < 0x7f {
                u16buf.push(ch as u8 as char);
            } else {
                if u16buf.len() >= min_len { result.push(u16buf.clone()); }
                u16buf.clear();
            }
            i += 2;
        }
        if u16buf.len() >= min_len && result.len() < 1200 { result.push(u16buf); }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    result.retain(|s| seen.insert(s.clone()));
    result
}

fn classify_string(s: &str) -> Option<&'static str> {
    // regex removed
    // Static patterns — compiled once per call, but that's fine for a scanner
    lazy_static_classify(s)
}

fn lazy_static_classify(s: &str) -> Option<&'static str> {
    // Simple prefix/contains checks for speed
    let sl = s.to_lowercase();
    if sl.starts_with("http://") || sl.starts_with("https://") { return Some("url"); }
    // IP address
    if s.len() <= 15 && s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) { return Some("ip"); }
    }
    if s.len() >= 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic() && (s.contains('\\') || s.contains('/')) { return Some("path"); }
    if sl.starts_with("hkey_") || sl.starts_with("hklm") || sl.starts_with("hkcu") || sl.starts_with("hkcr") { return Some("registry"); }
    // Anti-debug
    const ANTIDEBUG: &[&str] = &["IsDebuggerPresent","CheckRemoteDebugger","NtQueryInformationProcess","ZwQueryInformationProcess","OutputDebugString","DebugBreak","SetUnhandledExceptionFilter","BlockInput","NtSetInformationThread","DebugActiveProcess","UnhandledExceptionFilter","RtlQueryProcessHeapInformation","NtGlobalFlag"];
    for &ad in ANTIDEBUG { if s.contains(ad) { return Some("antidebug"); } }
    // Anti-VM
    const ANTIVM: &[&str] = &["vmware","virtualbox","vbox","qemu","sandbox","wine","cuckoomon","wireshark","ollydbg","x32dbg","x64dbg","procmon","processhacker","vmusrvc","vmtoolsd","vboxservice"];
    for &av in ANTIVM { if sl.contains(av) { return Some("antivm"); } }
    // Protection
    const PROTECTION: &[&str] = &["arxan","enigma","execryptor","nspack","obsidium","armadillo","acprotect","asprotect","safedisc","securom","starforce","steam_api"];
    for &p in PROTECTION { if sl.contains(p) { return Some("protection"); } }
    // Crypto
    const CRYPTO: &[&str] = &["CryptAcquire","CryptEncrypt","BCrypt","CryptGenKey","RijndaelManaged","EVP_","mbedtls_","wolfSSL"];
    if sl.contains("aes") || sl.contains("rsa") || sl.contains("rc4") || sl.contains("sha") || sl.contains("md5") {
        return Some("crypto");
    }
    for &c in CRYPTO { if s.contains(c) { return Some("crypto"); } }
    // Network
    const NETWORK: &[&str] = &["WSAStartup","HttpOpen","InternetOpen","WinHttpOpen","curl_","libcurl","gethostbyname"];
    if sl.contains("socket") || sl.contains("connect") || sl.contains("recv") || sl.contains("send") {
        return Some("network");
    }
    for &n in NETWORK { if s.contains(n) { return Some("network"); } }
    // Mutex
    if s.contains("CreateMutex") || s.contains("OpenMutex") { return Some("mutex"); }
    // Injection
    const INJECT: &[&str] = &["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx","QueueUserAPC","SetWindowsHookEx","RtlCreateUserThread"];
    for &inj in INJECT { if s.contains(inj) { return Some("injection"); } }
    // Ransom
    if sl.contains("your files") && sl.contains("encrypt") { return Some("ransom"); }
    if sl.contains("ransom") || sl.contains("bitcoin") && sl.contains("decrypt") { return Some("ransom"); }
    if sl.contains("vssadmin") && sl.contains("delete") { return Some("ransom"); }

    None
}

/// Packer section-name signatures
fn detect_packer_section(name: &str) -> Option<&'static str> {
    let lo = name.to_lowercase();
    if lo.starts_with(".upx") || lo == "upx0" || lo == "upx1" || lo == "upx2" { return Some("UPX"); }
    if lo.starts_with(".mpress") { return Some("MPRESS"); }
    if lo == ".aspack" { return Some("ASPack"); }
    if lo == ".petite" { return Some("Petite"); }
    if lo.starts_with(".pec") { return Some("PECompact"); }
    if lo.starts_with("nsp") { return Some("NSPack"); }
    if lo == ".te!" { return Some("tElock"); }
    if lo.starts_with(".exec") { return Some("EXEcryptor"); }
    if lo.starts_with("enigma") { return Some("Enigma"); }
    None
}

/// EP byte-prefix packer signatures
const PACKER_EP_SIGS_RS: &[(&str, &[u8])] = &[
    ("UPX",    &[0x60, 0xBE]),
    ("MPRESS", &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]),
    ("ASPack", &[0x60, 0xE8, 0x72, 0x00]),
    ("FSG",    &[0xBE, 0x88]),
];

#[tauri::command]
fn scan_pe_full(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    if data.len() < 0x40 { return Err("Dosya çok küçük".into()); }
    if data[0] != 0x4D || data[1] != 0x5A { return Err("MZ signature bulunamadı".into()); }

    let pe_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_off + 4 > data.len() { return Err("Geçersiz PE offset".into()); }
    if &data[pe_off..pe_off+4] != b"PE\0\0" { return Err("PE signature bulunamadı".into()); }

    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let is_64 = pe.is_64;
    let image_base = pe.image_base;
    let ep_rva = pe.entry;
    let num_sec = pe.sections.len();
    let is_dll = (pe.header.coff_header.characteristics & 0x2000) != 0;

    // ── Compile timestamp ─────────────────────────────────────────
    let compiled_ts = pe.header.coff_header.time_date_stamp;
    let compiled_at = if compiled_ts > 0 {
        chrono_ts(compiled_ts)
    } else { None };
    let fake_timestamp = compiled_at.as_ref().map(|ts| {
        ts.contains("199") || ts.starts_with("198") || ts.starts_with("197") || {
            // future check
            compiled_ts > 2000000000 // ~2033
        }
    }).unwrap_or(false);

    // ── Rich Header ───────────────────────────────────────────────
    let rich_hash = parse_rich_header(&data, pe_off);

    // ── .NET CLR ──────────────────────────────────────────────────
    let is_dotnet = pe.header.optional_header
        .map(|oh| oh.data_directories.get_clr_runtime_header().is_some())
        .unwrap_or(false);

    // ── Overlay ───────────────────────────────────────────────────
    let mut last_section_end: usize = 0;
    for s in &pe.sections {
        let end = s.pointer_to_raw_data as usize + s.size_of_raw_data as usize;
        if end > last_section_end { last_section_end = end; }
    }
    let overlay_size = if last_section_end > 0 && data.len() > last_section_end + 512 {
        data.len() - last_section_end
    } else { 0 };

    // ── Sections + protection detection ───────────────────────────
    let mut sections_json = Vec::new();
    let mut denuvo = false;
    let mut vmp = false;
    let mut themida = false;
    let mut packers: Vec<String> = Vec::new();
    let mut suspicious_count = 0;

    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        let raw = s.pointer_to_raw_data as usize;
        let rsz = s.size_of_raw_data as usize;
        let vsz = s.virtual_size as usize;
        let chars = s.characteristics;
        let is_exec = (chars & 0x2000_0000) != 0;
        let writable = (chars & 0x8000_0000) != 0;
        let entropy = if rsz > 0 && raw + rsz <= data.len() {
            calc_entropy_rs(&data[raw..(raw + rsz).min(raw + 65536).min(data.len())])
        } else { 0.0 };

        let lo = name.to_lowercase();
        if lo.contains("denuvo") || (entropy > 7.55 && rsz > 512 * 1024 && is_exec) { denuvo = true; }
        if lo.contains(".vmp") { vmp = true; }
        if lo.contains(".themida") { themida = true; }

        if let Some(packer) = detect_packer_section(&name) {
            if !packers.contains(&packer.to_string()) { packers.push(packer.to_string()); }
        }

        let suspicious = entropy > 7.2 && rsz > 4096;
        if suspicious { suspicious_count += 1; }

        sections_json.push(serde_json::json!({
            "name": if name.is_empty() { "(unnamed)".to_string() } else { name },
            "vsize": vsz,
            "vaddr": s.virtual_address,
            "rsize": rsz,
            "rawOff": raw,
            "entropy": (entropy * 1000.0).round() / 1000.0,
            "isExec": is_exec,
            "writable": writable,
            "suspicious": suspicious,
        }));
    }

    // ── EP file offset + packer EP sigs ───────────────────────────
    let ep_file_off = pe.sections.iter().find_map(|s| {
        let vs = s.virtual_address as usize;
        let ve = vs + s.virtual_size as usize;
        if ep_rva >= vs && ep_rva < ve {
            Some(s.pointer_to_raw_data as usize + (ep_rva - vs))
        } else { None }
    }).unwrap_or(0);

    if ep_file_off > 0 && ep_file_off + 16 < data.len() {
        for &(name, sig) in PACKER_EP_SIGS_RS {
            if !packers.contains(&name.to_string()) &&
               sig.iter().enumerate().all(|(i, &b)| ep_file_off + i < data.len() && data[ep_file_off + i] == b) {
                packers.push(name.to_string());
            }
        }
    }

    // ── EP bytes ──────────────────────────────────────────────────
    let ep_bytes: Vec<String> = if ep_file_off > 0 && ep_file_off + 8 < data.len() {
        let end = (ep_file_off + 256).min(data.len());
        data[ep_file_off..end].iter().map(|b| format!("{:02X}", b)).collect()
    } else { vec![] };

    // ── Overall entropy ───────────────────────────────────────────
    let overall_entropy = calc_entropy_rs(&data[..data.len().min(524288)]);

    // ── Strings + classification ──────────────────────────────────
    let raw_strings = extract_strings_rs(&data, 5);
    let mut has_antidebug = false;
    let mut has_antivm = false;
    let strings_json: Vec<serde_json::Value> = raw_strings.iter().map(|s| {
        let cat = classify_string(s);
        if cat == Some("antidebug") { has_antidebug = true; }
        if cat == Some("antivm") { has_antivm = true; }
        serde_json::json!({
            "text": s,
            "cat": cat.map(|c| serde_json::json!({ "cat": c }))
        })
    }).collect();

    // ── Imports ───────────────────────────────────────────────────
    let mut dll_map: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for imp in &pe.imports {
        let funcs = dll_map.entry(imp.dll.to_lowercase()).or_default();
        funcs.push(imp.name.to_string());
    }
    // Check imports for anti-debug/anti-vm
    for funcs in dll_map.values() {
        for f in funcs {
            if classify_string(f) == Some("antidebug") { has_antidebug = true; }
            if classify_string(f) == Some("antivm") { has_antivm = true; }
        }
    }
    let imports_json: Vec<serde_json::Value> = dll_map.iter().map(|(dll, funcs)| {
        serde_json::json!({ "dll": dll, "funcs": funcs })
    }).collect();

    // ── Anti-debug/VM from strings + imports combined ─────────────
    let all_text = raw_strings.join(" ") + &pe.imports.iter().map(|i| i.name.as_ref()).collect::<Vec<_>>().join(" ");
    if !has_antidebug {
        for ad in &["IsDebuggerPresent","CheckRemoteDebugger","NtQueryInformationProcess"] {
            if all_text.contains(ad) { has_antidebug = true; break; }
        }
    }
    if !has_antivm {
        for av in &["vmware","virtualbox","vbox","qemu","sandbox"] {
            if all_text.to_lowercase().contains(av) { has_antivm = true; break; }
        }
    }

    // ── Risk score ────────────────────────────────────────────────
    let risk_score = ((if denuvo { 60 } else { 0 }) +
        (if vmp { 35 } else { 0 }) +
        (if themida { 25 } else { 0 }) +
        (if overall_entropy > 7.0 { 15 } else if overall_entropy > 6.5 { 8 } else { 0 }) +
        suspicious_count * 5 +
        (if has_antidebug { 10 } else { 0 }) +
        (if has_antivm { 8 } else { 0 }) +
        packers.len() as i32 * 12 +
        (if overlay_size > 0 { 10 } else { 0 }) +
        (if fake_timestamp { 8 } else { 0 })
    ).min(100);

    // ── Exports ───────────────────────────────────────────────────
    let exports_json: Vec<serde_json::Value> = pe.exports.iter().filter_map(|e| {
        Some(serde_json::json!({
            "name": e.name.as_deref().unwrap_or(""),
            "ordinal": 0,
            "rva": format!("0x{:08X}", e.rva),
        }))
    }).collect();

    // ── Hashing (MD5, SHA1, SHA256, CRC32, imphash) ───────────────
    use sha2::Digest as _;
    let sha256 = format!("{:x}", sha2::Sha256::digest(&data));
    let sha1_val = format!("{:x}", sha1::Sha1::digest(&data));
    let md5_val = format!("{:x}", md5::Md5::digest(&data));
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in &data { crc ^= b as u32; for _ in 0..8 { crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 }; } }
    let crc32_val = format!("{:08X}", crc ^ 0xFFFF_FFFF);

    // Imphash
    let imphash = {
        let csv: String = dll_map.iter().flat_map(|(dll, funcs)| {
            let d = dll.trim_end_matches(".dll").trim_end_matches(".ocx").trim_end_matches(".sys");
            funcs.iter().map(move |f| format!("{}.{}", d, f.to_lowercase()))
        }).collect::<Vec<_>>().join(",");
        if csv.is_empty() { String::new() } else {
            format!("{:x}", sha1::Sha1::digest(csv.as_bytes()))
        }
    };

    // ── TLS ───────────────────────────────────────────────────────
    let has_tls = pe.sections.iter().any(|s| {
        let n = String::from_utf8_lossy(&s.name);
        n.starts_with(".tls") || n.starts_with("TLS")
    });

    // ── Exception (.pdata) ────────────────────────────────────────
    let exception_entries = pe.sections.iter()
        .find(|s| s.name.starts_with(b".pdata"))
        .map(|s| s.size_of_raw_data as usize / 12)
        .unwrap_or(0);

    // ── Delayed imports ───────────────────────────────────────────
    let delayed_imports: Vec<String> = pe.imports.iter()
        .filter(|i| i.name == "__delayLoadHelper2" || i.dll.to_lowercase().contains("delayimp"))
        .map(|i| i.dll.to_string())
        .collect();

    // ── Debug PDB path ────────────────────────────────────────────
    let debug_pdb = {
        const RSDS: &[u8] = b"RSDS";
        data.windows(4).position(|w| w == RSDS).and_then(|pos| {
            let start = pos + 24;
            if start >= data.len() { return None; }
            let rest = &data[start..];
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len().min(260));
            let s = String::from_utf8_lossy(&rest[..end]).to_string();
            if s.ends_with(".pdb") || s.contains('\\') || s.contains('/') { Some(s) } else { None }
        }).unwrap_or_default()
    };

    // ── Code caves ────────────────────────────────────────────────
    let mut code_caves: Vec<serde_json::Value> = Vec::new();
    for s in &pe.sections {
        if s.characteristics & 0x2000_0000 == 0 { continue; }
        let raw = s.pointer_to_raw_data as usize;
        let rsz = s.size_of_raw_data as usize;
        if raw == 0 || rsz == 0 || raw + rsz > data.len() { continue; }
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        let mut run = 0usize;
        let mut run_start = 0usize;
        for i in 0..rsz {
            if data[raw + i] == 0x00 {
                if run == 0 { run_start = i; }
                run += 1;
            } else {
                if run >= 16 {
                    code_caves.push(serde_json::json!({ "section": name, "fileOff": raw + run_start, "size": run }));
                }
                run = 0;
            }
            if code_caves.len() > 50 { break; }
        }
        if run >= 16 { code_caves.push(serde_json::json!({ "section": name, "fileOff": raw + run_start, "size": run })); }
        if code_caves.len() > 50 { break; }
    }
    code_caves.sort_by(|a, b| b["size"].as_u64().unwrap_or(0).cmp(&a["size"].as_u64().unwrap_or(0)));
    code_caves.truncate(20);

    // ── WRX sections ──────────────────────────────────────────────
    let wrx_sections: Vec<String> = pe.sections.iter()
        .filter(|s| (s.characteristics & 0x2000_0000) != 0 && (s.characteristics & 0x8000_0000) != 0)
        .map(|s| String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string())
        .collect();

    // ── Packing ratios ────────────────────────────────────────────
    let packing_ratios: Vec<serde_json::Value> = pe.sections.iter().map(|s| {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        let vsz = s.virtual_size as f64;
        let rsz = s.size_of_raw_data as f64;
        serde_json::json!({
            "name": name, "raw": rsz as u64, "virt": vsz as u64,
            "ratio": if vsz > 0.0 { format!("{:.3}", rsz / vsz) } else { "—".into() }
        })
    }).collect();

    // ── PE checksum ───────────────────────────────────────────────
    let pe_checksum_off = pe_off + 24 + 64;
    let pe_checksum = if pe_checksum_off + 4 <= data.len() {
        u32::from_le_bytes([data[pe_checksum_off], data[pe_checksum_off+1], data[pe_checksum_off+2], data[pe_checksum_off+3]])
    } else { 0 };

    // ── Resources ─────────────────────────────────────────────────
    let resources = extract_resources_rs(&data, pe_off, is_64);

    // ── Subsystem ─────────────────────────────────────────────────
    let subsys_off = pe_off + 24 + if is_64 { 68 } else { 68 };
    let subsystem = if subsys_off + 2 <= data.len() {
        u16::from_le_bytes([data[subsys_off], data[subsys_off+1]])
    } else { 0 };

    // ── YARA-like rules (evaluated in Rust) ───────────────────────
    let yara_matches = evaluate_yara_rules(denuvo, vmp, themida, has_antidebug, has_antivm,
        overall_entropy, suspicious_count, &packers, overlay_size, is_dotnet, ep_rva,
        &imports_json, &strings_json, &rich_hash, &wrx_sections);

    Ok(serde_json::json!({
        "ep": ep_rva,
        "arch": if is_64 { "x64" } else { "x86" },
        "numSec": num_sec,
        "sections": sections_json,
        "denuvo": denuvo,
        "vmp": vmp,
        "themida": themida,
        "overallEntropy": (overall_entropy * 1000.0).round() / 1000.0,
        "suspiciousCount": suspicious_count,
        "riskScore": risk_score,
        "strings": strings_json,
        "imports": imports_json,
        "antiDebug": has_antidebug,
        "antiVM": has_antivm,
        "packers": packers,
        "exports": exports_json,
        "compiledAt": compiled_at,
        "fakeTimestamp": fake_timestamp,
        "sha256": sha256,
        "sha1": sha1_val,
        "imphash": imphash,
        "isDotNet": is_dotnet,
        "isDll": is_dll,
        "overlaySize": overlay_size,
        "richHash": rich_hash,
        "checksumOk": if pe_checksum == 0 { serde_json::Value::Null } else { serde_json::json!(true) },
        "epBytes": ep_bytes,
        "epFileOff": ep_file_off,
        "codeCaves": code_caves,
        "wrxSections": wrx_sections,
        "packingRatios": packing_ratios,
        "md5": md5_val,
        "crc32": crc32_val,
        "hasTls": has_tls,
        "exceptionEntries": exception_entries,
        "delayedImports": delayed_imports,
        "debugPdb": debug_pdb,
        "resources": resources,
        "yaraMatches": yara_matches,
        "fileSize": data.len(),
        "imageBase": format!("0x{:08X}", image_base),
        "subsystem": subsystem,
        // Scanner identifier
        "_scanner": "rust",
    }))
}

fn chrono_ts(ts: u32) -> Option<String> {
    let secs = ts as i64;
    // Simple epoch to ISO string
    let dt = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64);
    let datetime: std::time::SystemTime = dt;
    // Format as ISO 8601 manually
    let dur = datetime.duration_since(std::time::UNIX_EPOCH).ok()?;
    let total_secs = dur.as_secs();
    let days = total_secs / 86400;
    let time_secs = total_secs % 86400;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;
    // Approximate date from days since epoch (1970-01-01)
    let (y, mo, d) = days_to_date(days);
    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s))
}

fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let dy = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if days < dy { break; }
        days -= dy; y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0u64;
    for &md in &mdays {
        if days < md { break; }
        days -= md; mo += 1;
    }
    (y, mo + 1, days + 1)
}

fn parse_rich_header(data: &[u8], pe_off: usize) -> Option<String> {
    let rich_magic: u32 = 0x68636952; // 'Rich'
    for i in (0x80..pe_off.saturating_sub(4)).step_by(4) {
        if i + 8 > data.len() { break; }
        let val = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
        if val == rich_magic {
            let key = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]);
            let dans_magic: u32 = 0x536E6144;
            let mut entries = Vec::new();
            let mut j = 0x80;
            while j + 8 <= i {
                let cv  = u32::from_le_bytes([data[j], data[j+1], data[j+2], data[j+3]]) ^ key;
                let cnt = u32::from_le_bytes([data[j+4], data[j+5], data[j+6], data[j+7]]) ^ key;
                if cv != dans_magic {
                    let prod_id = (cv >> 16) & 0xFFFF;
                    let vs_id   = cv & 0xFFFF;
                    if prod_id > 0 || vs_id > 0 {
                        entries.push(format!("{:04x}.{:04x}:{}", prod_id, vs_id, cnt));
                    }
                }
                j += 8;
            }
            if !entries.is_empty() {
                return Some(entries.into_iter().take(12).collect::<Vec<_>>().join(" | "));
            }
            break;
        }
    }
    None
}

fn extract_resources_rs(data: &[u8], pe_off: usize, is_64: bool) -> Vec<serde_json::Value> {
    let mut resources = Vec::new();
    if pe_off + 24 + 4 > data.len() { return resources; }

    let dir_base = pe_off + 24 + if is_64 { 112 } else { 96 };
    // Resource directory = DataDirectory[2]
    let rsrc_rva_off = dir_base + 2 * 8;
    if rsrc_rva_off + 8 > data.len() { return resources; }
    let rsrc_rva = u32::from_le_bytes([data[rsrc_rva_off], data[rsrc_rva_off+1], data[rsrc_rva_off+2], data[rsrc_rva_off+3]]) as usize;
    let rsrc_size = u32::from_le_bytes([data[rsrc_rva_off+4], data[rsrc_rva_off+5], data[rsrc_rva_off+6], data[rsrc_rva_off+7]]) as usize;
    if rsrc_rva == 0 || rsrc_size == 0 { return resources; }

    let num_sec = u16::from_le_bytes([data[pe_off+6], data[pe_off+7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off+20], data[pe_off+21]]) as usize;
    let sec_base = pe_off + 24 + opt_size;

    // Find file offset of rsrc RVA
    let mut rsrc_raw = 0usize;
    for i in 0..num_sec {
        let b = sec_base + i * 40;
        if b + 40 > data.len() { break; }
        let va = u32::from_le_bytes([data[b+12], data[b+13], data[b+14], data[b+15]]) as usize;
        let vsz = u32::from_le_bytes([data[b+8], data[b+9], data[b+10], data[b+11]]) as usize;
        let raw = u32::from_le_bytes([data[b+20], data[b+21], data[b+22], data[b+23]]) as usize;
        if rsrc_rva >= va && rsrc_rva < va + vsz {
            rsrc_raw = raw + (rsrc_rva - va);
            break;
        }
    }
    if rsrc_raw == 0 || rsrc_raw + 16 > data.len() { return resources; }

    let type_names: std::collections::HashMap<u32, &str> = [
        (1, "Cursor"), (2, "Bitmap"), (3, "Icon"), (4, "Menu"), (5, "Dialog"),
        (6, "String"), (9, "Accelerator"), (10, "RCData"), (14, "Manifest"),
        (16, "VersionInfo"), (17, "Toolbar"),
    ].iter().cloned().collect();

    // Read root directory
    if rsrc_raw + 16 > data.len() { return resources; }
    let num_named = u16::from_le_bytes([data[rsrc_raw+12], data[rsrc_raw+13]]) as usize;
    let num_id = u16::from_le_bytes([data[rsrc_raw+14], data[rsrc_raw+15]]) as usize;

    for i in 0..(num_named + num_id).min(32) {
        let ent_off = rsrc_raw + 16 + i * 8;
        if ent_off + 8 > data.len() { break; }
        let type_id = u32::from_le_bytes([data[ent_off], data[ent_off+1], data[ent_off+2], data[ent_off+3]]) & 0x7FFFFFFF;
        let data_off_val = u32::from_le_bytes([data[ent_off+4], data[ent_off+5], data[ent_off+6], data[ent_off+7]]);
        let is_dir = (data_off_val & 0x80000000) != 0;
        if is_dir {
            let sub_off = (data_off_val & 0x7FFFFFFF) as usize + rsrc_raw;
            if sub_off + 16 <= data.len() {
                let sub_named = u16::from_le_bytes([data[sub_off+12], data[sub_off+13]]) as usize;
                let sub_id = u16::from_le_bytes([data[sub_off+14], data[sub_off+15]]) as usize;
                resources.push(serde_json::json!({
                    "type": type_id,
                    "name": type_names.get(&type_id).unwrap_or(&"Unknown"),
                    "count": sub_named + sub_id,
                }));
            }
        }
    }

    resources
}

fn evaluate_yara_rules(
    denuvo: bool, vmp: bool, themida: bool,
    anti_debug: bool, anti_vm: bool,
    entropy: f64, suspicious_count: i32,
    packers: &[String], overlay_size: usize,
    is_dotnet: bool, ep_rva: usize,
    imports: &[serde_json::Value],
    strings: &[serde_json::Value],
    rich_hash: &Option<String>,
    wrx_sections: &[String],
) -> Vec<serde_json::Value> {
    let mut matches = Vec::new();

    let has_cat = |cat: &str| -> bool {
        strings.iter().any(|s| s["cat"]["cat"].as_str() == Some(cat))
    };

    if denuvo { matches.push(serde_json::json!({"id":"denuvo_drm","name":"Denuvo Anti-Tamper","sev":"critical"})); }
    if vmp { matches.push(serde_json::json!({"id":"vmp_protect","name":"VMProtect","sev":"critical"})); }
    if themida { matches.push(serde_json::json!({"id":"themida","name":"Themida Protection","sev":"critical"})); }
    if anti_debug && anti_vm && entropy > 7.0 {
        matches.push(serde_json::json!({"id":"anti_trifecta","name":"Anti-Analysis Trifecta","sev":"critical","desc":"Anti-debug + Anti-VM + Yüksek entropi kombinasyonu"}));
    }
    if has_cat("crypto") && has_cat("network") {
        matches.push(serde_json::json!({"id":"crypto_net","name":"Crypto + Network","sev":"high","desc":"C2 beacon veya şifreli iletişim belirtisi"}));
    }
    if has_cat("ip") { matches.push(serde_json::json!({"id":"ip_hardcoded","name":"Hardcoded IP","sev":"high"})); }
    if anti_debug { matches.push(serde_json::json!({"id":"anti_debug","name":"Anti-Debug Detected","sev":"high"})); }
    if anti_vm { matches.push(serde_json::json!({"id":"anti_vm","name":"Anti-VM Detected","sev":"high"})); }
    if !packers.is_empty() {
        matches.push(serde_json::json!({"id":"packer_found","name":"Packer Detected","sev":"warn","desc":format!("Tespit edilen packer(lar): {}", packers.join(", "))}));
    }
    if has_cat("url") { matches.push(serde_json::json!({"id":"url_embedded","name":"Embedded URL","sev":"medium"})); }
    if has_cat("registry") { matches.push(serde_json::json!({"id":"registry_access","name":"Registry Access","sev":"medium"})); }
    if has_cat("mutex") { matches.push(serde_json::json!({"id":"mutex_creation","name":"Mutex Creation","sev":"medium"})); }
    if suspicious_count >= 3 { matches.push(serde_json::json!({"id":"many_suspicious","name":"Multiple Suspicious Sections","sev":"medium"})); }
    if imports.is_empty() { matches.push(serde_json::json!({"id":"no_imports","name":"Zero Imports (Suspicious)","sev":"high"})); }
    if is_dotnet { matches.push(serde_json::json!({"id":"clr_dotnet","name":".NET CLR Binary","sev":"warn"})); }
    if ep_rva == 0 && !imports.is_empty() {
        matches.push(serde_json::json!({"id":"zero_ep","name":"Suspicious Zero Entry Point","sev":"high","desc":"Entry point at 0x0 with imports — may indicate reflective loading"}));
    }
    if rich_hash.is_some() { matches.push(serde_json::json!({"id":"rich_header","name":"Rich Header Present","sev":"medium","desc":format!("Rich hash: {}", rich_hash.as_deref().unwrap_or(""))})); }
    if overlay_size > 0 { matches.push(serde_json::json!({"id":"overlay_large","name":"Large Overlay Data","sev":"warn","desc":format!("{:.1} KB overlay data", overlay_size as f64 / 1024.0)})); }
    if packers.len() >= 2 { matches.push(serde_json::json!({"id":"multi_packers","name":"Multiple Packers Stacked","sev":"critical","desc":format!("Double-packed: {}", packers.join(" + "))})); }
    if !wrx_sections.is_empty() { matches.push(serde_json::json!({"id":"wrx_section","name":"Writable+Executable Section","sev":"high","desc":format!("WRX sections: {}", wrx_sections.join(", "))})); }

    matches
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 3.2 — Multi-packer detection & generic unpack
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn try_unpack(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;

    // Detect packer type
    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(pe)) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let mut detected: Vec<String> = Vec::new();
    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        if let Some(p) = detect_packer_section(&name) { if !detected.contains(&p.to_string()) { detected.push(p.to_string()); } }
    }

    // Try UPX first
    if detected.contains(&"UPX".to_string()) {
        let result = std::process::Command::new("upx")
            .args(["--decompress", "--force", "--backup", &file_path])
            .output();
        match result {
            Ok(o) if o.status.success() => {
                return Ok(serde_json::json!({
                    "ok": true, "packer": "UPX",
                    "msg": String::from_utf8_lossy(&o.stdout).trim().to_string(),
                    "method": "upx --decompress"
                }));
            }
            _ => {}
        }
    }

    // Generic entropy-based unpack attempt:
    // Find section with highest entropy + executable → likely packed code
    // Write unpacked PE stub by zeroing out section characteristics
    let mut highest_entropy_sec: Option<(usize, f64, String)> = None;
    for s in &pe.sections {
        let raw = s.pointer_to_raw_data as usize;
        let rsz = s.size_of_raw_data as usize;
        if rsz == 0 || raw + rsz > data.len() { continue; }
        if s.characteristics & 0x2000_0000 == 0 { continue; } // not executable
        let ent = calc_entropy_rs(&data[raw..raw+rsz.min(65536)]);
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        if ent > 7.0 {
            if highest_entropy_sec.is_none() || ent > highest_entropy_sec.as_ref().unwrap().1 {
                highest_entropy_sec = Some((raw, ent, name));
            }
        }
    }

    if let Some((offset, ent, sec_name)) = highest_entropy_sec {
        // Report — we can't generically unpack without knowing the algorithm,
        // but we can provide useful info
        Ok(serde_json::json!({
            "ok": false,
            "packer": detected.first().unwrap_or(&"Unknown".to_string()).clone(),
            "detected_packers": detected,
            "msg": format!("Otomatik unpack başarısız. En yüksek entropi section: {} (entropy: {:.2}) @ offset 0x{:X}. Manuel analiz gerekli.", sec_name, ent, offset),
            "packed_section": sec_name,
            "packed_entropy": ent,
            "packed_offset": offset,
            "suggestion": if detected.contains(&"ASPack".to_string()) {
                "ASPack: stripper veya OllyDbg ile ESP trick kullanın".to_string()
            } else if detected.contains(&"PECompact".to_string()) {
                "PECompact: UnPECompact aracını deneyin".to_string()
            } else if detected.contains(&"MPRESS".to_string()) {
                "MPRESS: Generic OEP finder ile deneyin".to_string()
            } else if detected.contains(&"Petite".to_string()) {
                "Petite: un-petite aracını deneyin".to_string()
            } else {
                "Generic packer: dinamik analiz ile OEP bulup dump edin".to_string()
            },
        }))
    } else {
        Ok(serde_json::json!({
            "ok": false,
            "packer": detected.first().cloned().unwrap_or_default(),
            "detected_packers": detected,
            "msg": "Packed section tespit edilemedi veya entropy düşük",
        }))
    }
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 3.3 — Enhanced memory dump analysis
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn analyze_dump_enhanced(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let size = data.len();

    // Check for Windows minidump header (MDMP signature)
    let is_minidump = data.len() >= 32 && &data[0..4] == b"MDMP";
    let mut dump_info = serde_json::json!({});

    if is_minidump {
        // Parse MINIDUMP_HEADER
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let num_streams = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let stream_dir_rva = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let timestamp = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        // Parse stream directory entries
        let mut streams = Vec::new();
        let stream_names = std::collections::HashMap::from([
            (3u32, "ThreadList"), (4, "ModuleList"), (5, "MemoryList"),
            (6, "Exception"), (7, "SystemInfo"), (9, "ThreadInfoList"),
            (11, "Memory64List"), (12, "CommentA"), (13, "CommentW"),
            (14, "HandleData"), (15, "FunctionTable"), (16, "UnloadedModuleList"),
        ]);

        for i in 0..num_streams.min(64) {
            let off = stream_dir_rva as usize + i as usize * 12;
            if off + 12 > data.len() { break; }
            let stream_type = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
            let data_size = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
            let data_rva = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]);
            streams.push(serde_json::json!({
                "type": stream_type,
                "name": stream_names.get(&stream_type).unwrap_or(&"Unknown"),
                "size": data_size,
                "offset": data_rva,
            }));
        }

        dump_info = serde_json::json!({
            "format": "MDMP (Windows Minidump)",
            "version": version,
            "num_streams": num_streams,
            "timestamp": chrono_ts(timestamp),
            "streams": streams,
        });
    }

    // Find embedded PE images
    let mut pe_images: Vec<serde_json::Value> = Vec::new();
    let mut i = 0;
    while i < data.len().saturating_sub(64) && pe_images.len() < 20 {
        if data[i] == 0x4D && data[i + 1] == 0x5A {
            // Validate PE signature
            if i + 0x40 < data.len() {
                let pe_off = u32::from_le_bytes([data[i+0x3C], data[i+0x3D], data[i+0x3E], data[i+0x3F]]) as usize;
                if pe_off < 0x1000 && i + pe_off + 4 < data.len() {
                    if &data[i+pe_off..i+pe_off+4] == b"PE\0\0" {
                        // Valid PE found
                        let is_64 = if i + pe_off + 26 < data.len() {
                            u16::from_le_bytes([data[i+pe_off+24], data[i+pe_off+25]]) == 0x20B
                        } else { false };
                        let num_sec = u16::from_le_bytes([data[i+pe_off+6], data[i+pe_off+7]]) as usize;

                        // Estimate PE size from sections
                        let opt_size = u16::from_le_bytes([data[i+pe_off+20], data[i+pe_off+21]]) as usize;
                        let sec_base = pe_off + 24 + opt_size;
                        let mut pe_end = 0usize;
                        for s in 0..num_sec.min(96) {
                            let sb = i + sec_base + s * 40;
                            if sb + 40 > data.len() { break; }
                            let raw = u32::from_le_bytes([data[sb+20], data[sb+21], data[sb+22], data[sb+23]]) as usize;
                            let rsz = u32::from_le_bytes([data[sb+16], data[sb+17], data[sb+18], data[sb+19]]) as usize;
                            if raw + rsz > pe_end { pe_end = raw + rsz; }
                        }

                        pe_images.push(serde_json::json!({
                            "offset": format!("0x{:X}", i),
                            "offset_val": i,
                            "arch": if is_64 { "x64" } else { "x86" },
                            "sections": num_sec,
                            "estimated_size": pe_end,
                            "can_extract": pe_end > 0 && i + pe_end <= data.len(),
                        }));

                        if pe_end > 0 { i += pe_end; continue; }
                    }
                }
            }
        }
        i += 1;
    }

    // Memory regions — detect distinct entropy zones
    let chunk_size = 4096;
    let mut regions: Vec<serde_json::Value> = Vec::new();
    let mut prev_ent: f64 = -1.0;
    let mut region_start = 0;
    let mut region_type = "unknown";

    for chunk_idx in 0..(size / chunk_size).min(1024) {
        let off = chunk_idx * chunk_size;
        let end = (off + chunk_size).min(size);
        let ent = calc_entropy_rs(&data[off..end]);

        let cur_type = if ent < 0.5 { "zero/sparse" }
            else if ent < 3.0 { "structured" }
            else if ent < 6.0 { "code/data" }
            else if ent < 7.5 { "compressed" }
            else { "encrypted/random" };

        if cur_type != region_type && chunk_idx > 0 {
            regions.push(serde_json::json!({
                "start": format!("0x{:X}", region_start),
                "end": format!("0x{:X}", off),
                "size": off - region_start,
                "type": region_type,
                "entropy": (prev_ent * 100.0).round() / 100.0,
            }));
            region_start = off;
        }
        region_type = cur_type;
        prev_ent = ent;
    }
    if region_start < size {
        regions.push(serde_json::json!({
            "start": format!("0x{:X}", region_start),
            "end": format!("0x{:X}", size),
            "size": size - region_start,
            "type": region_type,
            "entropy": (prev_ent * 100.0).round() / 100.0,
        }));
    }

    // Overall entropy
    let overall_ent = calc_entropy_rs(&data[..size.min(524288)]);

    // Strings sample
    let strings = extract_strings_rs(&data, 5);

    Ok(serde_json::json!({
        "size": size,
        "entropy": (overall_ent * 1000.0).round() / 1000.0,
        "is_minidump": is_minidump,
        "dump_info": dump_info,
        "pe_images": pe_images,
        "pe_count": pe_images.len(),
        "memory_regions": regions,
        "strings_sample": strings.into_iter().take(100).collect::<Vec<_>>(),
        "is_likely_dump": pe_images.len() > 1 || (overall_ent > 5.0 && overall_ent < 7.5),
    }))
}

/// Extract embedded PE from dump at given offset
#[tauri::command]
fn extract_pe_from_dump(dump_path: String, offset: u64, output_path: String) -> Result<String, String> {
    let data = std::fs::read(&dump_path).map_err(|e| e.to_string())?;
    let off = offset as usize;
    if off + 0x40 >= data.len() { return Err("Offset geçersiz".into()); }
    if data[off] != 0x4D || data[off+1] != 0x5A { return Err("MZ signature bulunamadı".into()); }

    let pe_off = u32::from_le_bytes([data[off+0x3C], data[off+0x3D], data[off+0x3E], data[off+0x3F]]) as usize;
    if off + pe_off + 4 >= data.len() { return Err("PE header dışarıda".into()); }

    let num_sec = u16::from_le_bytes([data[off+pe_off+6], data[off+pe_off+7]]) as usize;
    let opt_size = u16::from_le_bytes([data[off+pe_off+20], data[off+pe_off+21]]) as usize;
    let sec_base = pe_off + 24 + opt_size;

    let mut pe_end = sec_base + num_sec * 40; // at minimum, headers
    for s in 0..num_sec.min(96) {
        let sb = off + sec_base + s * 40;
        if sb + 40 > data.len() { break; }
        let raw = u32::from_le_bytes([data[sb+20], data[sb+21], data[sb+22], data[sb+23]]) as usize;
        let rsz = u32::from_le_bytes([data[sb+16], data[sb+17], data[sb+18], data[sb+19]]) as usize;
        if raw + rsz > pe_end { pe_end = raw + rsz; }
    }

    if off + pe_end > data.len() { pe_end = data.len() - off; }

    std::fs::write(&output_path, &data[off..off+pe_end]).map_err(|e| e.to_string())?;
    Ok(format!("PE extracted: {} bytes → {}", pe_end, output_path))
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 3.4 — ssdeep-style fuzzy hashing (CTPH)
// ══════════════════════════════════════════════════════════════════════

fn fnv_hash(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for &b in data {
        h = h.wrapping_mul(0x01000193) ^ (b as u32);
    }
    h
}

/// Context-Triggered Piecewise Hashing (simplified ssdeep-like)
#[tauri::command]
fn fuzzy_hash(file_path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let size = data.len();
    if size < 64 { return Err("Dosya çok küçük".into()); }

    // Determine block size (auto-scale based on file size)
    let mut block_size = 3;
    while block_size * 64 < size { block_size *= 2; }
    let block_size2 = block_size * 2;

    let base64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Rolling hash (Adler32-like)
    let trigger = |rolling: u32, bs: usize| -> bool { rolling % (bs as u32) == (bs as u32 - 1) };

    let mut hash1 = Vec::new();
    let mut hash2 = Vec::new();
    let mut rolling: u32 = 0;
    let window_size = 7;

    let mut h1_accum: u32 = 0x28021967;
    let mut h2_accum: u32 = 0x28021967;

    for (i, &b) in data.iter().enumerate() {
        // Simple rolling hash
        rolling = rolling.wrapping_add(b as u32);
        if i >= window_size { rolling = rolling.wrapping_sub(data[i - window_size] as u32); }

        h1_accum = h1_accum.wrapping_mul(0x01000193) ^ (b as u32);
        h2_accum = h2_accum.wrapping_mul(0x01000193) ^ (b as u32);

        if trigger(h1_accum, block_size) {
            hash1.push(base64_chars[(h1_accum % 64) as usize] as char);
            h1_accum = 0x28021967;
        }
        if trigger(h2_accum, block_size2) {
            hash2.push(base64_chars[(h2_accum % 64) as usize] as char);
            h2_accum = 0x28021967;
        }
    }
    // Final characters
    hash1.push(base64_chars[(h1_accum % 64) as usize] as char);
    hash2.push(base64_chars[(h2_accum % 64) as usize] as char);

    // Truncate to 64 chars max
    hash1.truncate(64);
    hash2.truncate(64);

    let fuzzy = format!("{}:{}:{}", block_size, hash1.iter().collect::<String>(), hash2.iter().collect::<String>());

    Ok(serde_json::json!({
        "fuzzy_hash": fuzzy,
        "block_size": block_size,
        "file_size": size,
    }))
}

/// Compare two fuzzy hashes — returns similarity 0-100
#[tauri::command]
fn fuzzy_compare(hash1: String, hash2: String) -> Result<serde_json::Value, String> {
    // Parse "blocksize:hash1:hash2" format
    let parts1: Vec<&str> = hash1.splitn(3, ':').collect();
    let parts2: Vec<&str> = hash2.splitn(3, ':').collect();
    if parts1.len() != 3 || parts2.len() != 3 { return Err("Geçersiz hash formatı".into()); }

    let bs1: usize = parts1[0].parse().map_err(|_| "BS1 parse hatası")?;
    let bs2: usize = parts2[0].parse().map_err(|_| "BS2 parse hatası")?;

    // Block sizes must be related (same, double, or half)
    let (h1, h2) = if bs1 == bs2 {
        (parts1[1], parts2[1])
    } else if bs1 == bs2 * 2 {
        (parts1[2], parts2[1])
    } else if bs2 == bs1 * 2 {
        (parts1[1], parts2[2])
    } else {
        return Ok(serde_json::json!({ "score": 0, "reason": "Block size uyumsuz" }));
    };

    // Levenshtein-based similarity
    let score = string_similarity(h1, h2);

    Ok(serde_json::json!({
        "score": score,
        "block_size_match": bs1 == bs2,
    }))
}

fn string_similarity(a: &str, b: &str) -> u32 {
    if a.is_empty() || b.is_empty() { return 0; }
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let max_len = a_bytes.len().max(b_bytes.len());

    // LCS length
    let mut prev = vec![0u16; b_bytes.len() + 1];
    let mut curr = vec![0u16; b_bytes.len() + 1];
    for i in 0..a_bytes.len() {
        for j in 0..b_bytes.len() {
            if a_bytes[i] == b_bytes[j] {
                curr[j + 1] = prev[j] + 1;
            } else {
                curr[j + 1] = curr[j].max(prev[j + 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.iter_mut().for_each(|v| *v = 0);
    }

    let lcs_len = *prev.iter().max().unwrap_or(&0) as usize;
    ((lcs_len * 100) / max_len) as u32
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 3.5 — Parallel batch scanning (rayon)
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn batch_scan(file_paths: Vec<String>, app: tauri::AppHandle) -> Result<Vec<serde_json::Value>, String> {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let total = file_paths.len();
    let done = std::sync::Arc::new(AtomicUsize::new(0));

    let results: Vec<serde_json::Value> = file_paths.par_iter().map(|path| {
        let result = match scan_pe_full_inner(path) {
            Ok(mut val) => {
                val.as_object_mut().unwrap().insert("_file".into(), serde_json::json!(path));
                val.as_object_mut().unwrap().insert("_status".into(), serde_json::json!("ok"));
                val
            }
            Err(e) => {
                // Try ELF/Mach-O
                match scan_generic(path) {
                    Ok(mut val) => {
                        val.as_object_mut().unwrap().insert("_file".into(), serde_json::json!(path));
                        val.as_object_mut().unwrap().insert("_status".into(), serde_json::json!("ok"));
                        val
                    }
                    Err(_) => serde_json::json!({
                        "_file": path,
                        "_status": "error",
                        "_error": e,
                    })
                }
            }
        };

        let completed = done.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = app.emit("batch-progress", serde_json::json!({
            "done": completed,
            "total": total,
            "pct": (completed as f64 / total as f64 * 100.0) as u8,
            "file": path,
        }));

        result
    }).collect();

    Ok(results)
}

/// Internal scan function without Tauri command wrapper
fn scan_pe_full_inner(file_path: &str) -> Result<serde_json::Value, String> {
    // Just delegate to scan_pe_full — but we need the path as String
    scan_pe_full(file_path.to_string())
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 3.6 — ELF / Mach-O support (multi-format scanner)
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn scan_generic(file_path: &str) -> Result<serde_json::Value, String> {
    let data = std::fs::read(file_path).map_err(|e| e.to_string())?;
    if data.len() < 16 { return Err("Dosya çok küçük".into()); }

    match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::Elf(elf) => scan_elf(&data, &elf, file_path),
        goblin::Object::Mach(mach) => scan_mach(&data, &mach, file_path),
        goblin::Object::PE(_) => scan_pe_full(file_path.to_string()),
        _ => Err("Desteklenmeyen dosya formatı".into()),
    }
}

fn scan_elf(data: &[u8], elf: &goblin::elf::Elf, _file_path: &str) -> Result<serde_json::Value, String> {
    let overall_entropy = calc_entropy_rs(&data[..data.len().min(524288)]);

    // Sections
    let sections: Vec<serde_json::Value> = elf.section_headers.iter().map(|s| {
        let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("");
        let off = s.sh_offset as usize;
        let sz = s.sh_size as usize;
        let entropy = if sz > 0 && off + sz <= data.len() {
            calc_entropy_rs(&data[off..(off + sz).min(off + 65536).min(data.len())])
        } else { 0.0 };
        serde_json::json!({
            "name": name,
            "type": format!("{:#x}", s.sh_type),
            "addr": format!("0x{:016X}", s.sh_addr),
            "offset": s.sh_offset,
            "size": s.sh_size,
            "entropy": (entropy * 1000.0).round() / 1000.0,
            "executable": (s.sh_flags & 0x4) != 0,  // SHF_EXECINSTR
            "writable": (s.sh_flags & 0x1) != 0,    // SHF_WRITE
        })
    }).collect();

    // Dynamic symbols
    let dynsyms: Vec<serde_json::Value> = elf.dynsyms.iter().take(500).map(|sym| {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        serde_json::json!({
            "name": name,
            "addr": format!("0x{:016X}", sym.st_value),
            "size": sym.st_size,
            "bind": match sym.st_bind() { 0 => "LOCAL", 1 => "GLOBAL", 2 => "WEAK", _ => "?" },
            "type": match sym.st_type() { 0 => "NOTYPE", 1 => "OBJECT", 2 => "FUNC", _ => "?" },
        })
    }).collect();

    // Libraries
    let libraries: Vec<String> = elf.libraries.iter().map(|l| l.to_string()).collect();

    // Strings
    let strings = extract_strings_rs(data, 5);

    // Hashing
    use sha2::Digest as _;
    let sha256 = format!("{:x}", sha2::Sha256::digest(data));
    let md5_val = format!("{:x}", md5::Md5::digest(data));

    let is_stripped = elf.syms.is_empty();
    let is_pie = elf.header.e_type == 3; // ET_DYN

    Ok(serde_json::json!({
        "_scanner": "rust",
        "_format": "ELF",
        "arch": match elf.header.e_machine {
            0x03 => "x86",
            0x3E => "x86_64",
            0x28 => "ARM",
            0xB7 => "AArch64",
            _ => "unknown",
        },
        "entry_point": format!("0x{:016X}", elf.entry),
        "is_pie": is_pie,
        "is_stripped": is_stripped,
        "type": match elf.header.e_type {
            1 => "Relocatable",
            2 => "Executable",
            3 => "Shared Object",
            4 => "Core",
            _ => "Unknown",
        },
        "sections": sections,
        "num_sections": sections.len(),
        "dynsyms": dynsyms,
        "libraries": libraries,
        "strings_sample": strings.into_iter().take(200).collect::<Vec<_>>(),
        "overallEntropy": (overall_entropy * 1000.0).round() / 1000.0,
        "sha256": sha256,
        "md5": md5_val,
        "fileSize": data.len(),
        "riskScore": 0, // placeholder
    }))
}

fn scan_mach(data: &[u8], mach: &goblin::mach::Mach, file_path: &str) -> Result<serde_json::Value, String> {
    match mach {
        goblin::mach::Mach::Binary(macho) => scan_macho_single(data, macho, file_path),
        goblin::mach::Mach::Fat(fat) => {
            // Multi-arch binary — scan first arch
            if let Some(arch) = fat.iter_arches().next() {
                let arch = arch.map_err(|e| e.to_string())?;
                let slice = &data[arch.offset as usize..(arch.offset + arch.size) as usize];
                if let Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) = goblin::Object::parse(slice) {
                    let mut result = scan_macho_single(slice, &macho, file_path)?;
                    result.as_object_mut().unwrap().insert("fat_arches".into(),
                        serde_json::json!(fat.iter_arches().count()));
                    return Ok(result);
                }
            }
            Err("Fat Mach-O okunamadı".into())
        }
    }
}

fn scan_macho_single(data: &[u8], macho: &goblin::mach::MachO, _file_path: &str) -> Result<serde_json::Value, String> {
    let overall_entropy = calc_entropy_rs(&data[..data.len().min(524288)]);

    let segments: Vec<serde_json::Value> = macho.segments.iter().map(|seg| {
        let name = seg.name().unwrap_or("?");
        let sections: Vec<serde_json::Value> = seg.sections().unwrap_or_default().iter().map(|(sec, _)| {
            let sec_name = sec.name().unwrap_or("?");
            serde_json::json!({
                "name": format!("{},{}", name, sec_name),
                "addr": format!("0x{:016X}", sec.addr),
                "size": sec.size,
            })
        }).collect();
        serde_json::json!({
            "name": name,
            "addr": format!("0x{:016X}", seg.vmaddr),
            "vmsize": seg.vmsize,
            "filesize": seg.filesize,
            "sections": sections,
        })
    }).collect();

    let libs: Vec<String> = macho.libs.iter().map(|l| l.to_string()).collect();
    let strings = extract_strings_rs(data, 5);

    use sha2::Digest as _;
    let sha256 = format!("{:x}", sha2::Sha256::digest(data));
    let md5_val = format!("{:x}", md5::Md5::digest(data));

    Ok(serde_json::json!({
        "_scanner": "rust",
        "_format": "Mach-O",
        "arch": if macho.is_64 { "x86_64/ARM64" } else { "x86/ARM" },
        "entry_point": format!("0x{:016X}", macho.entry),
        "type": if macho.header.filetype == 2 { "Executable" }
            else if macho.header.filetype == 6 { "Dylib" }
            else { "Other" },
        "segments": segments,
        "libraries": libs,
        "strings_sample": strings.into_iter().take(200).collect::<Vec<_>>(),
        "overallEntropy": (overall_entropy * 1000.0).round() / 1000.0,
        "sha256": sha256,
        "md5": md5_val,
        "fileSize": data.len(),
        "riskScore": 0,
    }))
}

// ── Disassembly — Entry Point (A1/A2) ────────────────────────────────
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

// ── Disassembly — Chunk-based (1.1) ──────────────────────────────────

#[derive(Serialize)]
struct DisasmChunk {
    instructions: Vec<serde_json::Value>,
    start_addr: u64,
    end_addr: u64,
    is_64: bool,
}

#[tauri::command]
fn disassemble_at(file_path: String, offset: u64, count: usize, is_virtual: bool) -> Result<DisasmChunk, String> {
    use capstone::prelude::*;

    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let image_base = pe.image_base as u64;
    let is_64 = pe.is_64;

    // Determine file offset and virtual address
    let (file_off, virt_addr) = if is_virtual {
        // offset is an RVA or VA — convert to file offset
        let rva = if offset >= image_base { offset - image_base } else { offset };
        let foff = pe.sections.iter().find_map(|s| {
            let vs = s.virtual_address as u64;
            let ve = vs + s.virtual_size as u64;
            if rva >= vs && rva < ve {
                Some(s.pointer_to_raw_data as u64 + (rva - vs))
            } else { None }
        }).ok_or_else(|| format!("RVA 0x{:X} section'da bulunamadı", rva))?;
        (foff as usize, image_base + rva)
    } else {
        // offset is a raw file offset — convert to VA for display
        let va = pe.sections.iter().find_map(|s| {
            let rs = s.pointer_to_raw_data as u64;
            let re = rs + s.size_of_raw_data as u64;
            if offset >= rs && offset < re {
                Some(image_base + s.virtual_address as u64 + (offset - rs))
            } else { None }
        }).unwrap_or(offset);
        (offset as usize, va)
    };

    if file_off >= data.len() {
        return Err(format!("Offset 0x{:X} dosya boyutunu aşıyor", file_off));
    }

    let max_bytes = (count * 15).min(data.len().saturating_sub(file_off));
    let code = &data[file_off..file_off + max_bytes];

    let cs = if is_64 {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build()
    } else {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).detail(true).build()
    }.map_err(|e| e.to_string())?;

    let insns = cs.disasm_count(code, virt_addr, count).map_err(|e| e.to_string())?;

    let mut end_addr = virt_addr;
    let instructions: Vec<serde_json::Value> = insns.iter().map(|i| {
        let mn = i.mnemonic().unwrap_or("").to_lowercase();
        let kind = if mn.starts_with("ret") { "ret" }
            else if mn.starts_with("call") { "call" }
            else if mn == "nop" || mn == "int3" { "nop" }
            else if mn.starts_with("jmp") || (mn.starts_with("j") && mn.len() <= 4) { "jmp" }
            else if mn.starts_with("j") { "jcc" }
            else if mn.starts_with("push") || mn.starts_with("pop") || mn.starts_with("mov") || mn.starts_with("lea") { "data" }
            else if mn.starts_with("cmp") || mn.starts_with("test") { "cmp" }
            else { "" };

        // Calculate branch target for CALL/JMP/Jcc
        let ops = i.op_str().unwrap_or("");
        let target: Option<u64> = if kind == "call" || kind == "jmp" || kind == "jcc" {
            // Try parsing "0x..." operand
            ops.trim().strip_prefix("0x")
                .and_then(|s| u64::from_str_radix(s, 16).ok())
        } else { None };

        end_addr = i.address() + i.bytes().len() as u64;

        let mut obj = serde_json::json!({
            "addr": format!("0x{:08X}", i.address()),
            "addr_val": i.address(),
            "offset": file_off as u64 + (i.address() - virt_addr),
            "bytes": i.bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
            "size": i.bytes().len(),
            "mnemonic": i.mnemonic().unwrap_or(""),
            "operands": ops,
            "kind": kind,
        });
        if let Some(t) = target {
            obj.as_object_mut().unwrap().insert("target".into(), serde_json::json!(format!("0x{:08X}", t)));
            obj.as_object_mut().unwrap().insert("target_val".into(), serde_json::json!(t));
        }
        obj
    }).collect();

    Ok(DisasmChunk {
        instructions,
        start_addr: virt_addr,
        end_addr,
        is_64,
    })
}

// ── Function boundary detection (1.2) ────────────────────────────────

#[derive(Serialize)]
struct FuncInfo {
    addr: String,
    addr_val: u64,
    file_offset: u64,
    size: u64,
    name: String,
    call_count: usize,
    is_entry: bool,
}

#[tauri::command]
fn list_functions(file_path: String) -> Result<Vec<FuncInfo>, String> {
    use capstone::prelude::*;

    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let image_base = pe.image_base as u64;
    let ep_rva = pe.entry as u64;

    // Collect import names for labeling
    let mut import_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for imp in &pe.imports {
        // IAT entries: these are targets of CALL [addr] instructions
        import_map.insert(image_base + imp.rva as u64, format!("{}!{}", imp.dll, imp.name));
    }

    // Collect export names
    let mut export_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for exp in &pe.exports {
        if let Some(name) = &exp.name {
            export_map.insert(image_base + exp.rva as u64, name.to_string());
        }
    }

    let cs = if pe.is_64 {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()
    } else {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build()
    }.map_err(|e| e.to_string())?;

    // Scan executable sections for function boundaries
    let mut call_targets: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    let mut func_starts: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    // Add EP as a known function
    func_starts.insert(image_base + ep_rva);

    // Add exports as known functions
    for exp in &pe.exports {
        func_starts.insert(image_base + exp.rva as u64);
    }

    for sec in &pe.sections {
        let chars = sec.characteristics;
        // Only scan executable sections
        if chars & 0x20000000 == 0 { continue; } // IMAGE_SCN_MEM_EXECUTE

        let raw_start = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        if raw_start + raw_size > data.len() { continue; }

        let sec_va = image_base + sec.virtual_address as u64;
        let code = &data[raw_start..raw_start + raw_size];

        if let Ok(insns) = cs.disasm_all(code, sec_va) {
            for i in insns.iter() {
                let mn = i.mnemonic().unwrap_or("").to_lowercase();
                if mn.starts_with("call") {
                    if let Some(target) = i.op_str().unwrap_or("")
                        .trim().strip_prefix("0x")
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                    {
                        *call_targets.entry(target).or_insert(0) += 1;
                        func_starts.insert(target);
                    }
                }
            }
        }
    }

    // Build function list — estimate size from gaps between starts
    let starts: Vec<u64> = func_starts.iter().copied().collect();
    let mut functions: Vec<FuncInfo> = Vec::new();

    for (idx, &addr) in starts.iter().enumerate() {
        let rva = addr.saturating_sub(image_base);

        // Convert to file offset
        let file_offset = pe.sections.iter().find_map(|s| {
            let vs = s.virtual_address as u64;
            let ve = vs + s.virtual_size as u64;
            if rva >= vs && rva < ve {
                Some(s.pointer_to_raw_data as u64 + (rva - vs))
            } else { None }
        });

        let file_offset = match file_offset {
            Some(f) if (f as usize) < data.len() => f,
            _ => continue, // Skip addresses outside file
        };

        // Estimate function size (distance to next function start in same section)
        let size = starts.get(idx + 1)
            .map(|next| next.saturating_sub(addr))
            .unwrap_or(64)
            .min(0x10000); // cap at 64KB

        // Name: export name > import name > "sub_ADDR"
        let name = export_map.get(&addr)
            .cloned()
            .unwrap_or_else(|| {
                if addr == image_base + ep_rva {
                    "EntryPoint".into()
                } else {
                    format!("sub_{:08X}", addr)
                }
            });

        let call_count = call_targets.get(&addr).copied().unwrap_or(0);

        functions.push(FuncInfo {
            addr: format!("0x{:08X}", addr),
            addr_val: addr,
            file_offset,
            size,
            name,
            call_count,
            is_entry: addr == image_base + ep_rva,
        });
    }

    // Sort: entry point first, then by call count descending
    functions.sort_by(|a, b| {
        b.is_entry.cmp(&a.is_entry)
            .then(b.call_count.cmp(&a.call_count))
    });

    // Limit to prevent huge payloads
    functions.truncate(2000);

    Ok(functions)
}

// ── CFG (Control Flow Graph) ──────────────────────────────────────────

#[derive(Serialize)]
struct CfgBlock {
    id: String,
    start_addr: u64,
    end_addr: u64,
    label: String,
    instructions: Vec<serde_json::Value>,
    block_type: String, // "entry","normal","exit","call","branch"
}

#[derive(Serialize)]
struct CfgEdge {
    source: String,
    target: String,
    edge_type: String, // "fallthrough","branch_true","branch_false","unconditional","call"
    label: String,
}

#[derive(Serialize)]
struct CfgResult {
    blocks: Vec<CfgBlock>,
    edges: Vec<CfgEdge>,
    func_name: String,
    func_addr: u64,
    is_64: bool,
}

#[tauri::command]
fn get_cfg(file_path: String, func_addr: u64, max_insns: Option<usize>) -> Result<CfgResult, String> {
    use capstone::prelude::*;
    use std::collections::{HashMap, HashSet};

    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let image_base = pe.image_base as u64;
    let is_64 = pe.is_64;
    let max_count = max_insns.unwrap_or(1000);

    // Convert VA to file offset
    let rva = if func_addr >= image_base { func_addr - image_base } else { func_addr };
    let file_off = pe.sections.iter().find_map(|s| {
        let vs = s.virtual_address as u64;
        let ve = vs + s.virtual_size as u64;
        if rva >= vs && rva < ve {
            Some(s.pointer_to_raw_data as u64 + (rva - vs))
        } else { None }
    }).ok_or_else(|| format!("RVA 0x{:X} section'da bulunamadı", rva))? as usize;

    if file_off >= data.len() {
        return Err("Offset dosya boyutunu aşıyor".into());
    }

    let max_bytes = (max_count * 15).min(data.len().saturating_sub(file_off));
    let code = &data[file_off..file_off + max_bytes];
    let base_va = image_base + rva;

    let cs = if is_64 {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build()
    } else {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).detail(true).build()
    }.map_err(|e| e.to_string())?;

    let insns = cs.disasm_count(code, base_va, max_count).map_err(|e| e.to_string())?;
    if insns.is_empty() {
        return Err("Talimat decode edilemedi".into());
    }

    // ── Phase 1: Linear scan — collect all instructions & find block boundaries ──
    struct InsInfo {
        addr: u64,
        size: u16,
        mnemonic: String,
        operands: String,
        bytes_hex: String,
        kind: String,       // ret, call, jmp, jcc, nop, data, cmp, ""
        target: Option<u64>,
    }

    let mut all_insns: Vec<InsInfo> = Vec::new();
    let mut block_starts: HashSet<u64> = HashSet::new();
    block_starts.insert(base_va); // function entry is always a block start

    for i in insns.iter() {
        let mn = i.mnemonic().unwrap_or("").to_lowercase();
        let op = i.op_str().unwrap_or("").to_string();
        let addr = i.address();
        let sz = i.bytes().len() as u16;
        let bytes_hex = i.bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");

        let kind = if mn.starts_with("ret") { "ret".to_string() }
            else if mn.starts_with("call") { "call".to_string() }
            else if mn == "nop" || mn == "int3" { "nop".to_string() }
            else if mn.starts_with("jmp") { "jmp".to_string() }
            else if mn.starts_with("j") && mn.len() <= 4 { "jcc".to_string() }
            else if mn.starts_with("j") { "jcc".to_string() }
            else if mn.starts_with("cmp") || mn.starts_with("test") { "cmp".to_string() }
            else if mn.starts_with("push") || mn.starts_with("pop") || mn.starts_with("mov") || mn.starts_with("lea") { "data".to_string() }
            else { "".to_string() };

        // Extract branch target
        let target = if kind == "jmp" || kind == "jcc" || kind == "call" {
            // Try parsing operand as hex address
            let clean = op.trim().trim_start_matches("0x");
            u64::from_str_radix(clean, 16).ok()
        } else { None };

        // Branch targets and instruction after branches are block starts
        if kind == "jmp" || kind == "jcc" || kind == "ret" {
            if let Some(t) = target {
                if t >= base_va && t < base_va + max_bytes as u64 {
                    block_starts.insert(t);
                }
            }
            // Instruction after a branch/ret = new block start (fallthrough)
            block_starts.insert(addr + sz as u64);
        }

        all_insns.push(InsInfo { addr, size: sz, mnemonic: mn, operands: op, bytes_hex, kind, target });
    }

    if all_insns.is_empty() {
        return Err("Hiç talimat bulunamadı".into());
    }

    // ── Phase 2: Build basic blocks ──
    // Sort block starts
    let mut sorted_starts: Vec<u64> = block_starts.iter().copied().collect();
    sorted_starts.sort();

    // Map: addr → instruction index
    let addr_to_idx: HashMap<u64, usize> = all_insns.iter().enumerate().map(|(i, ins)| (ins.addr, i)).collect();

    let func_end = all_insns.last().map(|i| i.addr + i.size as u64).unwrap_or(base_va);

    let mut blocks: Vec<CfgBlock> = Vec::new();
    let mut edges: Vec<CfgEdge> = Vec::new();

    for (bi, &start) in sorted_starts.iter().enumerate() {
        // Skip blocks outside our disassembled range
        if start >= func_end || !addr_to_idx.contains_key(&start) { continue; }

        // Find next block start to determine this block's end
        let next_start = sorted_starts.get(bi + 1).copied().unwrap_or(func_end);

        // Collect instructions in this block
        let mut block_insns: Vec<serde_json::Value> = Vec::new();
        let mut last_kind = String::new();
        let mut last_target: Option<u64> = None;
        let mut block_end = start;

        let start_idx = addr_to_idx[&start];
        for idx in start_idx..all_insns.len() {
            let ins = &all_insns[idx];
            if ins.addr >= next_start && ins.addr != start { break; }

            block_insns.push(serde_json::json!({
                "addr": format!("0x{:08X}", ins.addr),
                "addr_val": ins.addr,
                "mnemonic": ins.mnemonic,
                "operands": ins.operands,
                "bytes": ins.bytes_hex,
                "kind": ins.kind,
            }));

            last_kind = ins.kind.clone();
            last_target = ins.target;
            block_end = ins.addr + ins.size as u64;
        }

        if block_insns.is_empty() { continue; }

        let block_id = format!("blk_{:08X}", start);

        // Determine block type
        let block_type = if start == base_va { "entry" }
            else if last_kind == "ret" { "exit" }
            else if last_kind == "call" { "call" }
            else if last_kind == "jcc" || last_kind == "jmp" { "branch" }
            else { "normal" };

        blocks.push(CfgBlock {
            id: block_id.clone(),
            start_addr: start,
            end_addr: block_end,
            label: format!("0x{:08X}", start),
            instructions: block_insns,
            block_type: block_type.to_string(),
        });

        // ── Add edges ──
        match last_kind.as_str() {
            "ret" => {
                // No outgoing edges — function return
            },
            "jmp" => {
                // Unconditional jump
                if let Some(t) = last_target {
                    let target_id = format!("blk_{:08X}", t);
                    edges.push(CfgEdge {
                        source: block_id.clone(),
                        target: target_id,
                        edge_type: "unconditional".into(),
                        label: format!("0x{:08X}", t),
                    });
                }
            },
            "jcc" => {
                // Conditional jump — two edges: true (taken) + false (fallthrough)
                if let Some(t) = last_target {
                    let target_id = format!("blk_{:08X}", t);
                    edges.push(CfgEdge {
                        source: block_id.clone(),
                        target: target_id,
                        edge_type: "branch_true".into(),
                        label: "taken".into(),
                    });
                }
                // Fallthrough edge
                let ft_id = format!("blk_{:08X}", block_end);
                edges.push(CfgEdge {
                    source: block_id.clone(),
                    target: ft_id,
                    edge_type: "branch_false".into(),
                    label: "fall".into(),
                });
            },
            _ => {
                // Normal fallthrough to next block
                if block_end < func_end && block_end <= next_start {
                    let ft_id = format!("blk_{:08X}", block_end);
                    edges.push(CfgEdge {
                        source: block_id.clone(),
                        target: ft_id,
                        edge_type: "fallthrough".into(),
                        label: String::new(),
                    });
                }
            }
        }
    }

    // Filter edges — only keep edges to existing blocks
    let block_ids: HashSet<String> = blocks.iter().map(|b| b.id.clone()).collect();
    edges.retain(|e| block_ids.contains(&e.source) && block_ids.contains(&e.target));

    // Build func name from exports/imports
    let func_name = {
        let mut name = format!("sub_{:08X}", func_addr);
        for exp in &pe.exports {
            if let Some(n) = &exp.name {
                if image_base + exp.rva as u64 == func_addr {
                    name = n.to_string();
                    break;
                }
            }
        }
        name
    };

    Ok(CfgResult {
        blocks,
        edges,
        func_name,
        func_addr,
        is_64,
    })
}

// ── XRef (Cross-Reference) ───────────────────────────────────────────

#[derive(Serialize)]
struct XRefEntry {
    from_addr: String,
    from_addr_val: u64,
    to_addr: String,
    to_addr_val: u64,
    xref_type: String,   // "call","jmp","jcc","data"
    mnemonic: String,
    operands: String,
    context: String,      // function name or section containing the ref
}

#[derive(Serialize)]
struct XRefResult {
    target_addr: u64,
    target_name: String,
    refs_to: Vec<XRefEntry>,    // who references this address
    refs_from: Vec<XRefEntry>,  // what does this address reference
}

#[tauri::command]
fn get_xrefs(file_path: String, target_addr: u64) -> Result<XRefResult, String> {
    use capstone::prelude::*;
    use std::collections::HashMap;

    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let image_base = pe.image_base as u64;
    let is_64 = pe.is_64;

    // Build export/import name maps
    let mut name_map: HashMap<u64, String> = HashMap::new();
    for exp in &pe.exports {
        if let Some(n) = &exp.name {
            name_map.insert(image_base + exp.rva as u64, n.to_string());
        }
    }
    for imp in &pe.imports {
        name_map.insert(imp.rva as u64 + image_base, format!("{}!{}", imp.dll, imp.name));
    }

    let target_name = name_map.get(&target_addr)
        .cloned()
        .unwrap_or_else(|| format!("sub_{:08X}", target_addr));

    let cs = if is_64 {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build()
    } else {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).detail(true).build()
    }.map_err(|e| e.to_string())?;

    let mut refs_to: Vec<XRefEntry> = Vec::new();
    let mut refs_from: Vec<XRefEntry> = Vec::new();

    // Scan all executable sections
    for section in &pe.sections {
        let chars = section.characteristics;
        if chars & 0x20000000 == 0 { continue; } // IMAGE_SCN_MEM_EXECUTE

        let sec_name = String::from_utf8_lossy(
            &section.name[..section.name.iter().position(|&b| b == 0).unwrap_or(8)]
        ).to_string();

        let raw_off = section.pointer_to_raw_data as usize;
        let raw_sz = section.size_of_raw_data as usize;
        if raw_off + raw_sz > data.len() { continue; }

        let sec_va = image_base + section.virtual_address as u64;
        let code = &data[raw_off..raw_off + raw_sz];

        let insns = match cs.disasm_all(code, sec_va) {
            Ok(i) => i,
            Err(_) => continue,
        };

        for ins in insns.iter() {
            let mn = ins.mnemonic().unwrap_or("").to_lowercase();
            let op = ins.op_str().unwrap_or("").to_string();
            let addr = ins.address();

            let kind = if mn.starts_with("call") { "call" }
                else if mn.starts_with("jmp") { "jmp" }
                else if mn.starts_with("j") { "jcc" }
                else { continue };

            // Parse branch target
            let clean = op.trim().trim_start_matches("0x");
            let branch_target = match u64::from_str_radix(clean, 16) {
                Ok(t) => t,
                Err(_) => continue,
            };

            // refs_to: instructions that reference our target_addr
            if branch_target == target_addr {
                refs_to.push(XRefEntry {
                    from_addr: format!("0x{:08X}", addr),
                    from_addr_val: addr,
                    to_addr: format!("0x{:08X}", target_addr),
                    to_addr_val: target_addr,
                    xref_type: kind.to_string(),
                    mnemonic: mn.clone(),
                    operands: op.clone(),
                    context: sec_name.clone(),
                });
            }

            // refs_from: instructions AT target_addr that reference elsewhere
            if addr == target_addr {
                let target_name_out = name_map.get(&branch_target)
                    .cloned()
                    .unwrap_or_else(|| format!("0x{:08X}", branch_target));
                refs_from.push(XRefEntry {
                    from_addr: format!("0x{:08X}", addr),
                    from_addr_val: addr,
                    to_addr: format!("0x{:08X}", branch_target),
                    to_addr_val: branch_target,
                    xref_type: kind.to_string(),
                    mnemonic: mn.clone(),
                    operands: op.clone(),
                    context: target_name_out,
                });
            }
        }
    }

    // Also scan for data references (LEA, MOV with immediate matching target)
    // This catches string references and global variable access
    for section in &pe.sections {
        let raw_off = section.pointer_to_raw_data as usize;
        let raw_sz = section.size_of_raw_data as usize;
        if raw_off + raw_sz > data.len() { continue; }

        let sec_va = image_base + section.virtual_address as u64;
        let code = &data[raw_off..raw_off + raw_sz];

        // Search for target address bytes in the section (little-endian)
        let target_bytes_32 = (target_addr as u32).to_le_bytes();
        let target_bytes_64 = target_addr.to_le_bytes();

        let mut pos = 0;
        while pos + 4 <= code.len() {
            let found = if is_64 && pos + 8 <= code.len() && code[pos..pos + 8] == target_bytes_64 {
                true
            } else if code[pos..pos + 4] == target_bytes_32 {
                true
            } else {
                false
            };

            if found {
                let ref_va = sec_va + pos as u64;
                // Don't duplicate branch references we already found
                if !refs_to.iter().any(|r| r.from_addr_val == ref_va) {
                    let sec_name = String::from_utf8_lossy(
                        &section.name[..section.name.iter().position(|&b| b == 0).unwrap_or(8)]
                    ).to_string();
                    refs_to.push(XRefEntry {
                        from_addr: format!("0x{:08X}", ref_va),
                        from_addr_val: ref_va,
                        to_addr: format!("0x{:08X}", target_addr),
                        to_addr_val: target_addr,
                        xref_type: "data".to_string(),
                        mnemonic: "ref".to_string(),
                        operands: format!("→ 0x{:08X}", target_addr),
                        context: sec_name,
                    });
                }
            }
            pos += 1;
        }
    }

    // Sort and limit
    refs_to.sort_by_key(|r| r.from_addr_val);
    refs_to.truncate(500);

    Ok(XRefResult {
        target_addr,
        target_name,
        refs_to,
        refs_from,
    })
}

// ── Patch Instruction ────────────────────────────────────────────────

#[derive(Serialize)]
struct PatchResult {
    offset: u64,
    original_bytes: String,
    new_bytes: String,
    description: String,
}

#[tauri::command]
fn patch_instruction(file_path: String, addr: u64, patch_type: String) -> Result<PatchResult, String> {
    use capstone::prelude::*;

    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okunamadı: {}", e))?;
    let pe = match goblin::Object::parse(&data).map_err(|e| e.to_string())? {
        goblin::Object::PE(pe) => pe,
        _ => return Err("PE binary değil".into()),
    };

    let image_base = pe.image_base as u64;
    let is_64 = pe.is_64;

    // Convert VA to file offset
    let rva = if addr >= image_base { addr - image_base } else { addr };
    let file_off = pe.sections.iter().find_map(|s| {
        let vs = s.virtual_address as u64;
        let ve = vs + s.virtual_size as u64;
        if rva >= vs && rva < ve {
            Some(s.pointer_to_raw_data as u64 + (rva - vs))
        } else { None }
    }).ok_or_else(|| format!("RVA 0x{:X} section'da bulunamadı", rva))? as usize;

    if file_off >= data.len() {
        return Err("Offset dosya boyutunu aşıyor".into());
    }

    // Disassemble the target instruction to know its size
    let max_bytes = 15.min(data.len().saturating_sub(file_off));
    let code = &data[file_off..file_off + max_bytes];

    let cs = if is_64 {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build()
    } else {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).detail(true).build()
    }.map_err(|e| e.to_string())?;

    let insns = cs.disasm_count(code, addr, 1).map_err(|e| e.to_string())?;
    let ins = insns.iter().next().ok_or("Talimat decode edilemedi")?;
    let ins_size = ins.bytes().len();
    let original_bytes = ins.bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
    let mn = ins.mnemonic().unwrap_or("").to_string();
    let op = ins.op_str().unwrap_or("").to_string();

    let (new_bytes_vec, description) = match patch_type.as_str() {
        "nop" => {
            // NOP out the instruction
            let nops = vec![0x90u8; ins_size];
            (nops, format!("{} {} → NOP x{}", mn, op, ins_size))
        },
        "jmp" => {
            // If conditional jump, make it unconditional
            if ins_size >= 2 && ins.bytes()[0] == 0x0F && (ins.bytes()[1] >= 0x80 && ins.bytes()[1] <= 0x8F) {
                // Near Jcc (0F 80-8F) → JMP (E9 + padding)
                let mut patch = vec![0xE9];
                patch.extend_from_slice(&ins.bytes()[2..]);  // keep the offset
                while patch.len() < ins_size { patch.push(0x90); }
                (patch, format!("{} → JMP (forced)", mn))
            } else if ins_size >= 2 && ins.bytes()[0] >= 0x70 && ins.bytes()[0] <= 0x7F {
                // Short Jcc → JMP short (EB)
                let mut patch = vec![0xEB, ins.bytes()[1]];
                while patch.len() < ins_size { patch.push(0x90); }
                (patch, format!("{} → JMP short (forced)", mn))
            } else {
                return Err("Bu talimat JMP'ye dönüştürülemez".into());
            }
        },
        "invert" => {
            // Invert conditional jump
            if ins_size >= 2 && ins.bytes()[0] == 0x0F && (ins.bytes()[1] >= 0x80 && ins.bytes()[1] <= 0x8F) {
                let mut patch = ins.bytes().to_vec();
                patch[1] ^= 0x01; // Toggle least significant bit to invert condition
                let desc = format!("{} → {} (inverted)", mn, if patch[1] & 1 == 0 { "even" } else { "odd" });
                (patch, desc)
            } else if ins.bytes()[0] >= 0x70 && ins.bytes()[0] <= 0x7F {
                let mut patch = ins.bytes().to_vec();
                patch[0] ^= 0x01;
                (patch, format!("{} → inverted", mn))
            } else {
                return Err("Bu talimat invert edilemez (Jcc değil)".into());
            }
        },
        "ret" => {
            // Replace with RET
            let mut patch = vec![0xC3];
            while patch.len() < ins_size { patch.push(0x90); }
            (patch, format!("{} {} → RET", mn, op))
        },
        _ => return Err(format!("Bilinmeyen patch tipi: {}", patch_type)),
    };

    let new_bytes_hex = new_bytes_vec.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");

    // Write the patch to the file
    let mut patched_data = data;
    for (i, &b) in new_bytes_vec.iter().enumerate() {
        if file_off + i < patched_data.len() {
            patched_data[file_off + i] = b;
        }
    }
    std::fs::write(&file_path, &patched_data).map_err(|e| format!("Yazma hatası: {}", e))?;

    Ok(PatchResult {
        offset: file_off as u64,
        original_bytes,
        new_bytes: new_bytes_hex,
        description,
    })
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 8.1 — Real Process Enumeration (Windows API)
// ══════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
mod process_api {
    use serde::Serialize;
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::System::Threading::*;
    use windows::Win32::Foundation::*;

    #[derive(Serialize, Clone)]
    pub struct ProcessInfo {
        pub pid: u32,
        pub name: String,
        pub threads: u32,
        pub parent_pid: u32,
        pub exe_path: String,
        pub memory_kb: u64,
    }

    pub fn enumerate_processes() -> Vec<ProcessInfo> {
        let mut procs = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if let Ok(snap) = snap {
                let mut entry = PROCESSENTRY32W::default();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snap, &mut entry).is_ok() {
                    loop {
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                        );
                        let pid = entry.th32ProcessID;
                        let threads = entry.cntThreads;
                        let parent_pid = entry.th32ParentProcessID;

                        let mut exe_path = String::new();
                        let memory_kb;

                        // Try to open process for query
                        if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                            let mut buf = [0u16; 260];
                            let mut len = buf.len() as u32;
                            if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
                                exe_path = String::from_utf16_lossy(&buf[..len as usize]);
                            }
                            let _ = CloseHandle(handle);
                        }

                        // Memory via sysinfo (safer than direct API)
                        memory_kb = 0; // filled in bulk below

                        procs.push(ProcessInfo { pid, name, threads, parent_pid, exe_path, memory_kb });

                        if Process32NextW(snap, &mut entry).is_err() { break; }
                    }
                }
                let _ = CloseHandle(snap);
            }
        }

        // Enrich memory data via sysinfo
        use sysinfo::System;
        let mut sys = System::new();
        sys.refresh_processes();
        for proc_info in &mut procs {
            if let Some(p) = sys.process(sysinfo::Pid::from_u32(proc_info.pid)) {
                proc_info.memory_kb = p.memory() / 1024;
            }
        }

        procs
    }
}

#[tauri::command]
fn list_processes() -> Result<Vec<serde_json::Value>, String> {
    #[cfg(target_os = "windows")]
    {
        let procs = process_api::enumerate_processes();
        Ok(procs.iter().map(|p| serde_json::json!({
            "pid": p.pid,
            "name": p.name,
            "threads": p.threads,
            "parent_pid": p.parent_pid,
            "exe_path": p.exe_path,
            "memory_kb": p.memory_kb,
        })).collect())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Process enumeration only supported on Windows".into())
    }
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 8.2 — Real Memory Read (Windows API)
// ══════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
mod memory_api {
    use serde::Serialize;
    use windows::Win32::System::Threading::*;
    use windows::Win32::System::Memory::*;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::Foundation::*;

    #[derive(Serialize)]
    pub struct MemoryRegion {
        pub base_address: String,
        pub size: u64,
        pub state: String,
        pub protect: String,
        pub region_type: String,
    }

    fn protect_str(p: PAGE_PROTECTION_FLAGS) -> String {
        match p {
            PAGE_READONLY => "R--".into(),
            PAGE_READWRITE => "RW-".into(),
            PAGE_EXECUTE => "--X".into(),
            PAGE_EXECUTE_READ => "R-X".into(),
            PAGE_EXECUTE_READWRITE => "RWX".into(),
            PAGE_WRITECOPY => "WC-".into(),
            PAGE_EXECUTE_WRITECOPY => "WCX".into(),
            PAGE_NOACCESS => "---".into(),
            _ => format!("0x{:X}", p.0),
        }
    }

    pub fn query_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>, String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| format!("OpenProcess failed (PID {}): {}", pid, e))?;

            let mut regions = Vec::new();
            let mut address: usize = 0;

            loop {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const std::ffi::c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if result == 0 { break; }

                let state = match mbi.State {
                    MEM_COMMIT => "Commit",
                    MEM_RESERVE => "Reserve",
                    MEM_FREE => "Free",
                    _ => "Unknown",
                };
                let region_type = match mbi.Type {
                    MEM_IMAGE => "Image",
                    MEM_MAPPED => "Mapped",
                    MEM_PRIVATE => "Private",
                    _ => "-",
                };

                if mbi.State != MEM_FREE {
                    regions.push(MemoryRegion {
                        base_address: format!("0x{:016X}", mbi.BaseAddress as u64),
                        size: mbi.RegionSize as u64,
                        state: state.into(),
                        protect: protect_str(mbi.Protect),
                        region_type: region_type.into(),
                    });
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;
                if address == 0 { break; }
            }

            let _ = CloseHandle(handle);
            Ok(regions)
        }
    }

    pub fn read_process_mem(pid: u32, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        let read_size = size.min(4096);
        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, false, pid)
                .map_err(|e| format!("OpenProcess failed: {}", e))?;

            let mut buffer = vec![0u8; read_size];
            let mut bytes_read = 0usize;
            ReadProcessMemory(
                handle,
                addr as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                read_size,
                Some(&mut bytes_read),
            ).map_err(|e| format!("ReadProcessMemory failed at 0x{:X}: {}", addr, e))?;

            let _ = CloseHandle(handle);
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }
}

#[tauri::command]
fn query_memory_regions(pid: u32) -> Result<Vec<serde_json::Value>, String> {
    #[cfg(target_os = "windows")]
    {
        let regions = memory_api::query_memory_regions(pid)?;
        Ok(regions.iter().map(|r| serde_json::json!({
            "base_address": r.base_address,
            "size": r.size,
            "state": r.state,
            "protect": r.protect,
            "type": r.region_type,
        })).collect())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Memory query only supported on Windows".into())
    }
}

#[tauri::command]
fn read_process_memory(pid: u32, address: String, size: usize) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let addr = if address.starts_with("0x") || address.starts_with("0X") {
            u64::from_str_radix(&address[2..], 16).map_err(|_| "Invalid address")?
        } else {
            address.parse::<u64>().map_err(|_| "Invalid address")?
        };
        let bytes = memory_api::read_process_mem(pid, addr, size)?;
        Ok(hex::encode(&bytes))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Memory read only supported on Windows".into())
    }
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 8.3 — Real Debugger (Windows API)
// ══════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
mod debugger_api {
    use serde::Serialize;
    use windows::Win32::System::Threading::*;
    use windows::Win32::System::Diagnostics::Debug::*;
    use windows::Win32::Foundation::*;
    use std::sync::Mutex;
    use std::collections::HashMap;

    // Raw FFI for x64 CONTEXT (windows-rs 0.58 doesn't cleanly export GetThreadContext/CONTEXT for x64)
    #[repr(C, align(16))]
    pub struct CONTEXT64 {
        pub p1_home: u64, pub p2_home: u64, pub p3_home: u64, pub p4_home: u64,
        pub p5_home: u64, pub p6_home: u64,
        pub context_flags: u32, pub mx_csr: u32,
        pub seg_cs: u16, pub seg_ds: u16, pub seg_es: u16, pub seg_fs: u16, pub seg_gs: u16, pub seg_ss: u16,
        pub eflags: u32,
        pub dr0: u64, pub dr1: u64, pub dr2: u64, pub dr3: u64, pub dr6: u64, pub dr7: u64,
        pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64, pub rsp: u64, pub rbp: u64,
        pub rsi: u64, pub rdi: u64, pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
        pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64, pub rip: u64,
        pub flt_save: [u8; 512],
        pub vector_register: [u8; 416],
        pub vector_control: u64,
        pub debug_control: u64, pub last_branch_to_rip: u64, pub last_branch_from_rip: u64,
        pub last_exception_to_rip: u64, pub last_exception_from_rip: u64,
    }

    extern "system" {
        fn GetThreadContext(hthread: HANDLE, lpcontext: *mut CONTEXT64) -> i32;
    }

    const CONTEXT_AMD64: u32 = 0x00100000;
    const CONTEXT_ALL_AMD64: u32 = CONTEXT_AMD64 | 0x1F;

    static DEBUG_STATE: std::sync::LazyLock<Mutex<DebugState>> = std::sync::LazyLock::new(|| Mutex::new(DebugState::default()));

    #[derive(Default)]
    pub struct DebugState {
        pub attached_pid: Option<u32>,
        pub breakpoints: HashMap<u64, u8>,
    }

    #[derive(Serialize)]
    pub struct RegisterSet {
        pub rax: String, pub rbx: String, pub rcx: String, pub rdx: String,
        pub rsi: String, pub rdi: String, pub rsp: String, pub rbp: String,
        pub rip: String, pub r8: String, pub r9: String, pub r10: String,
        pub r11: String, pub r12: String, pub r13: String, pub r14: String,
        pub r15: String, pub eflags: String,
    }

    pub fn attach_debugger(pid: u32) -> Result<String, String> {
        unsafe {
            DebugActiveProcess(pid)
                .map_err(|e| format!("DebugActiveProcess failed (PID {}): {}. Run as Administrator.", pid, e))?;
        }
        let mut state = DEBUG_STATE.lock().unwrap();
        state.attached_pid = Some(pid);
        Ok(format!("Attached to PID {}", pid))
    }

    pub fn detach_debugger() -> Result<String, String> {
        let mut state = DEBUG_STATE.lock().unwrap();
        if let Some(pid) = state.attached_pid {
            unsafe { let _ = DebugActiveProcessStop(pid); }
            state.attached_pid = None;
            state.breakpoints.clear();
            Ok(format!("Detached from PID {}", pid))
        } else {
            Err("Not attached to any process".into())
        }
    }

    pub fn set_breakpoint(addr: u64) -> Result<String, String> {
        let mut state = DEBUG_STATE.lock().unwrap();
        let pid = state.attached_pid.ok_or("Not attached to any process")?;

        let orig_bytes = super::memory_api::read_process_mem(pid, addr, 1)
            .map_err(|e| format!("Read failed: {}", e))?;
        if orig_bytes.is_empty() { return Err("Could not read byte at address".into()); }

        unsafe {
            let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid)
                .map_err(|e| format!("OpenProcess: {}", e))?;
            let int3: u8 = 0xCC;
            let mut written = 0usize;
            WriteProcessMemory(
                handle,
                addr as *const std::ffi::c_void,
                &int3 as *const u8 as *const std::ffi::c_void,
                1,
                Some(&mut written),
            ).map_err(|e| format!("WriteProcessMemory: {}", e))?;
            let _ = CloseHandle(handle);
        }

        state.breakpoints.insert(addr, orig_bytes[0]);
        Ok(format!("Breakpoint set at 0x{:X}", addr))
    }

    pub fn get_registers(tid: u32) -> Result<RegisterSet, String> {
        unsafe {
            let handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid)
                .map_err(|e| format!("OpenThread: {}", e))?;

            SuspendThread(handle);

            let mut ctx: CONTEXT64 = std::mem::zeroed();
            ctx.context_flags = CONTEXT_ALL_AMD64;
            let result = GetThreadContext(handle, &mut ctx);

            ResumeThread(handle);
            let _ = CloseHandle(handle);

            if result == 0 {
                return Err(format!("GetThreadContext failed: error {}", std::io::Error::last_os_error()));
            }

            Ok(RegisterSet {
                rax: format!("0x{:016X}", ctx.rax),
                rbx: format!("0x{:016X}", ctx.rbx),
                rcx: format!("0x{:016X}", ctx.rcx),
                rdx: format!("0x{:016X}", ctx.rdx),
                rsi: format!("0x{:016X}", ctx.rsi),
                rdi: format!("0x{:016X}", ctx.rdi),
                rsp: format!("0x{:016X}", ctx.rsp),
                rbp: format!("0x{:016X}", ctx.rbp),
                rip: format!("0x{:016X}", ctx.rip),
                r8:  format!("0x{:016X}", ctx.r8),
                r9:  format!("0x{:016X}", ctx.r9),
                r10: format!("0x{:016X}", ctx.r10),
                r11: format!("0x{:016X}", ctx.r11),
                r12: format!("0x{:016X}", ctx.r12),
                r13: format!("0x{:016X}", ctx.r13),
                r14: format!("0x{:016X}", ctx.r14),
                r15: format!("0x{:016X}", ctx.r15),
                eflags: format!("0x{:08X}", ctx.eflags),
            })
        }
    }

    pub fn continue_execution() -> Result<String, String> {
        let state = DEBUG_STATE.lock().unwrap();
        let pid = state.attached_pid.ok_or("Not attached")?;
        unsafe {
            ContinueDebugEvent(pid, 0, DBG_CONTINUE)
                .map_err(|e| format!("ContinueDebugEvent: {}", e))?;
        }
        Ok("Continued".into())
    }
}

#[tauri::command]
fn attach_debugger(pid: u32) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    { debugger_api::attach_debugger(pid) }
    #[cfg(not(target_os = "windows"))]
    { Err("Debugger only supported on Windows".into()) }
}

#[tauri::command]
fn detach_debugger() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    { debugger_api::detach_debugger() }
    #[cfg(not(target_os = "windows"))]
    { Err("Debugger only supported on Windows".into()) }
}

#[tauri::command]
fn set_breakpoint(address: String) -> Result<String, String> {
    let addr = if address.starts_with("0x") || address.starts_with("0X") {
        u64::from_str_radix(&address[2..], 16).map_err(|_| "Invalid address")?
    } else {
        address.parse::<u64>().map_err(|_| "Invalid address")?
    };
    #[cfg(target_os = "windows")]
    { debugger_api::set_breakpoint(addr) }
    #[cfg(not(target_os = "windows"))]
    { Err("Debugger only supported on Windows".into()) }
}

#[tauri::command]
fn get_registers(thread_id: u32) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "windows")]
    {
        let regs = debugger_api::get_registers(thread_id)?;
        Ok(serde_json::to_value(regs).unwrap())
    }
    #[cfg(not(target_os = "windows"))]
    { Err("Debugger only supported on Windows".into()) }
}

#[tauri::command]
fn continue_execution() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    { debugger_api::continue_execution() }
    #[cfg(not(target_os = "windows"))]
    { Err("Debugger only supported on Windows".into()) }
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 8.4 — Disassemble from attached process memory
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn disassemble_memory(pid: u32, address: String, size: usize) -> Result<serde_json::Value, String> {
    let addr = if address.starts_with("0x") || address.starts_with("0X") {
        u64::from_str_radix(&address[2..], 16).map_err(|_| "Invalid address")?
    } else {
        address.parse::<u64>().map_err(|_| "Invalid address")?
    };
    let read_size = size.min(4096);

    #[cfg(target_os = "windows")]
    {
        let bytes = memory_api::read_process_mem(pid, addr, read_size)?;
        use capstone::prelude::*;
        let cs = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| format!("Capstone init: {}", e))?;

        let insns = cs.disasm_all(&bytes, addr)
            .map_err(|e| format!("Disassembly failed: {}", e))?;

        let instructions: Vec<serde_json::Value> = insns.iter().map(|ins| {
            let ins_bytes: Vec<String> = ins.bytes().iter().map(|b| format!("{:02X}", b)).collect();
            serde_json::json!({
                "addr": format!("0x{:016X}", ins.address()),
                "addr_val": ins.address(),
                "offset": ins.address() - addr,
                "bytes": ins_bytes.join(" "),
                "mnemonic": ins.mnemonic().unwrap_or("???"),
                "operands": ins.op_str().unwrap_or(""),
            })
        }).collect();

        Ok(serde_json::json!({
            "pid": pid,
            "base_addr": format!("0x{:016X}", addr),
            "instructions": instructions,
            "bytes_read": bytes.len(),
        }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Memory disassembly only supported on Windows".into())
    }
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 8.5 — Simple CPU Emulation (pure Rust, no external deps)
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn emulate_function(hex_bytes: String, arch: String, start_addr: u64, max_steps: Option<u64>) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;

    let bytes: Vec<u8> = (0..hex_bytes.len()/2)
        .map(|i| u8::from_str_radix(&hex_bytes[i*2..i*2+2], 16))
        .collect::<Result<Vec<_>,_>>()
        .map_err(|_| "Invalid hex bytes")?;

    let is_64 = arch == "x64";
    let steps = max_steps.unwrap_or(200).min(2000) as usize;

    let cs = Capstone::new()
        .x86()
        .mode(if is_64 { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;

    let insns = cs.disasm_all(&bytes, start_addr)
        .map_err(|e| format!("Disassembly: {}", e))?;

    // Simple register model
    let mut regs: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    if is_64 {
        for r in ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip"] {
            regs.insert(r.into(), 0);
        }
        regs.insert("rsp".into(), 0x7FFFFFFFE000);
        regs.insert("rip".into(), start_addr);
    } else {
        for r in ["eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"] { regs.insert(r.into(), 0); }
        regs.insert("esp".into(), 0x0019FF80);
        regs.insert("eip".into(), start_addr as u64);
    }
    regs.insert("zf".into(), 0);
    regs.insert("cf".into(), 0);

    // Memory (sparse)
    let mut mem: std::collections::HashMap<u64, u8> = std::collections::HashMap::new();
    for (i, &b) in bytes.iter().enumerate() { mem.insert(start_addr + i as u64, b); }

    let ip_reg = if is_64 { "rip" } else { "eip" };
    let sp_reg = if is_64 { "rsp" } else { "esp" };
    let mut trace = Vec::new();

    // Build address-to-instruction lookup
    let ins_vec: Vec<(u64, String, String, usize)> = insns.iter().map(|i| {
        (i.address(), i.mnemonic().unwrap_or("").to_string(), i.op_str().unwrap_or("").to_string(), i.len())
    }).collect();
    let addr_to_idx: std::collections::HashMap<u64, usize> = ins_vec.iter().enumerate().map(|(i, (a,_,_,_))| (*a, i)).collect();

    for step_n in 0..steps {
        let ip = *regs.get(ip_reg).unwrap();
        let idx = match addr_to_idx.get(&ip) { Some(&i) => i, None => break };
        let (addr, ref mn, ref ops, sz) = ins_vec[idx];

        // Simple interpreter for common instructions
        let mut next_ip = addr + sz as u64;
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();

        fn get_val(regs: &std::collections::HashMap<String, u64>, s: &str) -> Option<u64> {
            let s = s.trim();
            if let Some(v) = regs.get(s) { return Some(*v); }
            if s.starts_with("0x") { return u64::from_str_radix(&s[2..], 16).ok(); }
            s.parse::<u64>().ok()
        }

        match mn.as_str() {
            "mov" if parts.len() == 2 => {
                if let Some(v) = get_val(&regs, parts[1]) {
                    regs.insert(parts[0].to_string(), v);
                }
            }
            "xor" if parts.len() == 2 && parts[0] == parts[1] => {
                regs.insert(parts[0].to_string(), 0);
                regs.insert("zf".into(), 1);
            }
            "xor" if parts.len() == 2 => {
                let a = get_val(&regs, parts[0]).unwrap_or(0);
                let b = get_val(&regs, parts[1]).unwrap_or(0);
                let r = a ^ b;
                regs.insert(parts[0].to_string(), r);
                regs.insert("zf".into(), if r == 0 { 1 } else { 0 });
            }
            "add" if parts.len() == 2 => {
                let a = get_val(&regs, parts[0]).unwrap_or(0);
                let b = get_val(&regs, parts[1]).unwrap_or(0);
                regs.insert(parts[0].to_string(), a.wrapping_add(b));
            }
            "sub" if parts.len() == 2 => {
                let a = get_val(&regs, parts[0]).unwrap_or(0);
                let b = get_val(&regs, parts[1]).unwrap_or(0);
                regs.insert(parts[0].to_string(), a.wrapping_sub(b));
                regs.insert("zf".into(), if a == b { 1 } else { 0 });
                regs.insert("cf".into(), if a < b { 1 } else { 0 });
            }
            "inc" if parts.len() >= 1 => {
                let v = get_val(&regs, parts[0]).unwrap_or(0);
                regs.insert(parts[0].to_string(), v.wrapping_add(1));
            }
            "dec" if parts.len() >= 1 => {
                let v = get_val(&regs, parts[0]).unwrap_or(0);
                regs.insert(parts[0].to_string(), v.wrapping_sub(1));
            }
            "push" if parts.len() >= 1 => {
                let v = get_val(&regs, parts[0]).unwrap_or(0);
                let sp = regs.get(sp_reg).copied().unwrap_or(0);
                let new_sp = sp.wrapping_sub(if is_64 { 8 } else { 4 });
                regs.insert(sp_reg.into(), new_sp);
                for i in 0..(if is_64 { 8 } else { 4 }) {
                    mem.insert(new_sp + i as u64, ((v >> (i*8)) & 0xFF) as u8);
                }
            }
            "pop" if parts.len() >= 1 => {
                let sp = regs.get(sp_reg).copied().unwrap_or(0);
                let w = if is_64 { 8 } else { 4 };
                let mut v: u64 = 0;
                for i in 0..w { v |= (*mem.get(&(sp + i as u64)).unwrap_or(&0) as u64) << (i*8); }
                regs.insert(parts[0].to_string(), v);
                regs.insert(sp_reg.into(), sp.wrapping_add(w as u64));
            }
            "cmp" if parts.len() == 2 => {
                let a = get_val(&regs, parts[0]).unwrap_or(0);
                let b = get_val(&regs, parts[1]).unwrap_or(0);
                regs.insert("zf".into(), if a == b { 1 } else { 0 });
                regs.insert("cf".into(), if a < b { 1 } else { 0 });
            }
            "test" if parts.len() == 2 => {
                let a = get_val(&regs, parts[0]).unwrap_or(0);
                let b = get_val(&regs, parts[1]).unwrap_or(0);
                regs.insert("zf".into(), if (a & b) == 0 { 1 } else { 0 });
            }
            "jmp" if parts.len() >= 1 => {
                if let Some(target) = get_val(&regs, parts[0]) { next_ip = target; }
            }
            "je" | "jz" if parts.len() >= 1 => {
                if *regs.get("zf").unwrap_or(&0) == 1 {
                    if let Some(t) = get_val(&regs, parts[0]) { next_ip = t; }
                }
            }
            "jne" | "jnz" if parts.len() >= 1 => {
                if *regs.get("zf").unwrap_or(&0) == 0 {
                    if let Some(t) = get_val(&regs, parts[0]) { next_ip = t; }
                }
            }
            "nop" => {}
            "ret" => break,
            _ => {} // unhandled instruction — skip
        }

        regs.insert(ip_reg.into(), next_ip);

        // Record trace
        if is_64 {
            trace.push(serde_json::json!({
                "step": step_n, "addr": format!("0x{:X}", addr),
                "inst": format!("{} {}", mn, ops),
                "rip": format!("0x{:016X}", next_ip),
                "rax": format!("0x{:016X}", regs.get("rax").copied().unwrap_or(0)),
                "rcx": format!("0x{:016X}", regs.get("rcx").copied().unwrap_or(0)),
                "rdx": format!("0x{:016X}", regs.get("rdx").copied().unwrap_or(0)),
                "rsp": format!("0x{:016X}", regs.get("rsp").copied().unwrap_or(0)),
            }));
        } else {
            trace.push(serde_json::json!({
                "step": step_n, "addr": format!("0x{:X}", addr),
                "inst": format!("{} {}", mn, ops),
                "eip": format!("0x{:08X}", next_ip),
                "eax": format!("0x{:08X}", regs.get("eax").copied().unwrap_or(0)),
                "ecx": format!("0x{:08X}", regs.get("ecx").copied().unwrap_or(0)),
                "edx": format!("0x{:08X}", regs.get("edx").copied().unwrap_or(0)),
                "esp": format!("0x{:08X}", regs.get("esp").copied().unwrap_or(0)),
            }));
        }
    }

    Ok(serde_json::json!({
        "arch": arch,
        "start_addr": format!("0x{:X}", start_addr),
        "steps": trace.len(),
        "trace": trace,
    }))
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 8.6 — Network Capture (per-process connections)
// ══════════════════════════════════════════════════════════════════════

#[tauri::command]
fn get_process_connections(pid: u32) -> Result<Vec<serde_json::Value>, String> {
    #[cfg(target_os = "windows")]
    {
        // Use netstat-style approach via IP Helper API
        // Fallback to command-line netstat for reliability
        let output = std::process::Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output()
            .map_err(|e| format!("netstat failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut conns = Vec::new();

        for line in stdout.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let line_pid: u32 = parts[4].parse().unwrap_or(0);
                if pid == 0 || line_pid == pid {
                    conns.push(serde_json::json!({
                        "protocol": parts[0],
                        "local_addr": parts[1],
                        "remote_addr": parts[2],
                        "state": parts[3],
                        "pid": line_pid,
                    }));
                }
            }
        }

        // Also get UDP
        let output_udp = std::process::Command::new("netstat")
            .args(["-ano", "-p", "UDP"])
            .output()
            .map_err(|e| format!("netstat UDP failed: {}", e))?;

        let stdout_udp = String::from_utf8_lossy(&output_udp.stdout);
        for line in stdout_udp.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let line_pid: u32 = parts.last().and_then(|s| s.parse().ok()).unwrap_or(0);
                if pid == 0 || line_pid == pid {
                    conns.push(serde_json::json!({
                        "protocol": "UDP",
                        "local_addr": parts[1],
                        "remote_addr": parts.get(2).unwrap_or(&"*:*"),
                        "state": "-",
                        "pid": line_pid,
                    }));
                }
            }
        }

        Ok(conns)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Network capture only supported on Windows".into())
    }
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 10 — Collaborative & Cloud
// ══════════════════════════════════════════════════════════════════════

// 10.3 — Cloud YARA / IOC Feed
#[tauri::command]
async fn fetch_yara_rules(source: String) -> Result<serde_json::Value, String> {
    // Fetch community YARA rules from known sources
    let url = match source.as_str() {
        "abuse_ch" => "https://yaraify-api.abuse.ch/api/v1/",
        "yara_rules_repo" => "https://raw.githubusercontent.com/Yara-Rules/rules/master/index.yar",
        _ => return Err("Unknown YARA source".into()),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    if source == "abuse_ch" {
        let resp = client.post(url)
            .form(&[("query", "get_rules"), ("search_term", "")])
            .send().await.map_err(|e| e.to_string())?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body)
    } else {
        let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "rules": text, "source": source }))
    }
}

// 10.3 — Fetch IOC feeds
#[tauri::command]
async fn fetch_ioc_feed(feed_type: String) -> Result<serde_json::Value, String> {
    let url = match feed_type.as_str() {
        "malware_bazaar" => "https://mb-api.abuse.ch/api/v1/",
        "urlhaus" => "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "threatfox" => "https://threatfox-api.abuse.ch/api/v1/",
        _ => return Err("Unknown IOC feed".into()),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    if feed_type == "malware_bazaar" {
        let resp = client.post(url)
            .form(&[("query", "get_recent"), ("selector", "100")])
            .send().await.map_err(|e| e.to_string())?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body)
    } else if feed_type == "threatfox" {
        let resp = client.post(url)
            .json(&serde_json::json!({"query": "get_iocs", "days": 1}))
            .send().await.map_err(|e| e.to_string())?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body)
    } else {
        let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body)
    }
}

// 10.4 — Remote AI Backend (OpenAI / Anthropic / Groq compatible)
#[tauri::command]
async fn cloud_ai_chat(
    messages: Vec<serde_json::Value>,
    model: String,
    provider: String,
    api_key: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let (url, auth_header, body) = match provider.as_str() {
        "openai" => {
            let url = "https://api.openai.com/v1/chat/completions";
            let body = serde_json::json!({
                "model": model,
                "messages": messages,
                "stream": true,
                "max_tokens": 4096,
            });
            (url.to_string(), format!("Bearer {}", api_key), body)
        },
        "anthropic" => {
            let url = "https://api.anthropic.com/v1/messages";
            // Convert messages format for Anthropic
            let system_msg = messages.iter()
                .find(|m| m["role"] == "system")
                .and_then(|m| m["content"].as_str())
                .unwrap_or("");
            let conv_msgs: Vec<serde_json::Value> = messages.iter()
                .filter(|m| m["role"] != "system")
                .cloned().collect();
            let body = serde_json::json!({
                "model": model,
                "system": system_msg,
                "messages": conv_msgs,
                "stream": true,
                "max_tokens": 4096,
            });
            (url.to_string(), api_key.clone(), body)
        },
        "groq" => {
            let url = "https://api.groq.com/openai/v1/chat/completions";
            let body = serde_json::json!({
                "model": model,
                "messages": messages,
                "stream": true,
                "max_tokens": 4096,
            });
            (url.to_string(), format!("Bearer {}", api_key), body)
        },
        _ => return Err(format!("Unknown provider: {}", provider)),
    };

    let client = reqwest::Client::new();
    let mut req = client.post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string());

    if provider == "anthropic" {
        req = req.header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01");
    } else {
        req = req.header("Authorization", &auth_header);
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    let mut buf = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buf.find('\n') {
            let line = buf[..pos].to_string();
            buf = buf[pos + 1..].to_string();
            let line = line.trim();
            if line.is_empty() || line == "data: [DONE]" { continue; }
            if let Some(data) = line.strip_prefix("data: ") {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                    // OpenAI / Groq format
                    if let Some(delta) = json["choices"][0]["delta"]["content"].as_str() {
                        let _ = app.emit("chat-chunk", delta);
                    }
                    // Anthropic format
                    if let Some(text) = json["delta"]["text"].as_str() {
                        let _ = app.emit("chat-chunk", text);
                    }
                }
            }
        }
    }
    let _ = app.emit("chat-done", "");
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 11 — İLERİ BINARY ANALİZ
// ══════════════════════════════════════════════════════════════════════

// 11.1 — Simplified Symbolic Execution (path constraint tracking)
#[tauri::command]
fn symbolic_execute(hex_bytes: String, arch: String, start_addr: u64, max_steps: usize) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;
    let bytes = hex::decode(&hex_bytes).map_err(|e| format!("{}", e))?;
    let cs = Capstone::new()
        .x86()
        .mode(if arch == "x64" { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;
    let insns = cs.disasm_all(&bytes, start_addr).map_err(|e| format!("{}", e))?;

    let mut paths: Vec<serde_json::Value> = Vec::new();
    let mut constraints: Vec<String> = Vec::new();
    let mut path_addrs: Vec<u64> = Vec::new();
    let mut branch_count = 0u32;

    for (i, insn) in insns.as_ref().iter().enumerate() {
        if i >= max_steps { break; }
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");
        path_addrs.push(insn.address());

        match mnemonic {
            "je" | "jz" => {
                constraints.push(format!("ZF == 1 @ 0x{:x}", insn.address()));
                branch_count += 1;
                // Record both paths
                paths.push(serde_json::json!({
                    "branch_addr": format!("0x{:x}", insn.address()),
                    "type": "conditional",
                    "condition": "ZF == 1 (equal/zero)",
                    "target": operands,
                    "constraint": constraints.last(),
                }));
            },
            "jne" | "jnz" => {
                constraints.push(format!("ZF == 0 @ 0x{:x}", insn.address()));
                branch_count += 1;
                paths.push(serde_json::json!({
                    "branch_addr": format!("0x{:x}", insn.address()),
                    "type": "conditional",
                    "condition": "ZF == 0 (not equal/not zero)",
                    "target": operands,
                    "constraint": constraints.last(),
                }));
            },
            "jg" | "jnle" => {
                constraints.push(format!("ZF==0 && SF==OF @ 0x{:x}", insn.address()));
                branch_count += 1;
                paths.push(serde_json::json!({ "branch_addr": format!("0x{:x}", insn.address()), "type": "conditional", "condition": "greater", "target": operands }));
            },
            "jl" | "jnge" => {
                constraints.push(format!("SF!=OF @ 0x{:x}", insn.address()));
                branch_count += 1;
                paths.push(serde_json::json!({ "branch_addr": format!("0x{:x}", insn.address()), "type": "conditional", "condition": "less", "target": operands }));
            },
            "cmp" => {
                constraints.push(format!("cmp {} @ 0x{:x}", operands, insn.address()));
            },
            "test" => {
                constraints.push(format!("test {} @ 0x{:x}", operands, insn.address()));
            },
            "call" => {
                paths.push(serde_json::json!({
                    "branch_addr": format!("0x{:x}", insn.address()),
                    "type": "call",
                    "target": operands,
                }));
            },
            "ret" => {
                paths.push(serde_json::json!({
                    "branch_addr": format!("0x{:x}", insn.address()),
                    "type": "return",
                }));
                break;
            },
            _ => {}
        }
    }

    Ok(serde_json::json!({
        "paths": paths,
        "constraints": constraints,
        "path_addresses": path_addrs.iter().map(|a| format!("0x{:x}", a)).collect::<Vec<_>>(),
        "total_instructions": insns.as_ref().len(),
        "branch_count": branch_count,
        "arch": arch,
    }))
}

// 11.2 — Taint Analysis (track data flow through registers)
#[tauri::command]
fn taint_analysis(hex_bytes: String, arch: String, start_addr: u64, taint_sources: Vec<String>) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;
    let bytes = hex::decode(&hex_bytes).map_err(|e| format!("{}", e))?;
    let cs = Capstone::new()
        .x86()
        .mode(if arch == "x64" { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;
    let insns = cs.disasm_all(&bytes, start_addr).map_err(|e| format!("{}", e))?;

    // Track which registers are tainted
    let mut tainted: std::collections::HashSet<String> = taint_sources.into_iter().collect();
    let mut taint_log: Vec<serde_json::Value> = Vec::new();
    let mut dangerous_sinks: Vec<serde_json::Value> = Vec::new();

    for insn in insns.as_ref().iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");
        let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();

        match mnemonic {
            "mov" | "movzx" | "movsx" | "lea" if parts.len() == 2 => {
                let dst = parts[0].to_lowercase();
                let src = parts[1].to_lowercase();
                // If source is tainted, destination becomes tainted
                let src_tainted = tainted.iter().any(|t| src.contains(&t.to_lowercase()));
                if src_tainted {
                    tainted.insert(dst.clone());
                    taint_log.push(serde_json::json!({
                        "addr": format!("0x{:x}", insn.address()),
                        "inst": format!("{} {}", mnemonic, operands),
                        "action": "propagate",
                        "from": src, "to": dst,
                        "tainted_regs": tainted.iter().cloned().collect::<Vec<_>>(),
                    }));
                } else if tainted.contains(&dst) {
                    // Overwritten with clean value
                    tainted.remove(&dst);
                    taint_log.push(serde_json::json!({
                        "addr": format!("0x{:x}", insn.address()),
                        "inst": format!("{} {}", mnemonic, operands),
                        "action": "clean",
                        "register": dst,
                    }));
                }
            },
            "xor" if parts.len() == 2 && parts[0] == parts[1] => {
                let reg = parts[0].to_lowercase();
                tainted.remove(&reg);
            },
            "add" | "sub" | "xor" | "or" | "and" if parts.len() == 2 => {
                let dst = parts[0].to_lowercase();
                let src = parts[1].to_lowercase();
                if tainted.iter().any(|t| src.contains(&t.to_lowercase())) {
                    tainted.insert(dst.clone());
                    taint_log.push(serde_json::json!({
                        "addr": format!("0x{:x}", insn.address()),
                        "inst": format!("{} {}", mnemonic, operands),
                        "action": "propagate_arith",
                        "tainted_regs": tainted.iter().cloned().collect::<Vec<_>>(),
                    }));
                }
            },
            "push" if parts.len() == 1 => {
                let src = parts[0].to_lowercase();
                if tainted.iter().any(|t| src.contains(&t.to_lowercase())) {
                    taint_log.push(serde_json::json!({
                        "addr": format!("0x{:x}", insn.address()),
                        "inst": format!("{} {}", mnemonic, operands),
                        "action": "tainted_push",
                    }));
                }
            },
            "call" => {
                // Check if any argument register is tainted
                let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "eax", "ecx", "edx"];
                let tainted_args: Vec<String> = arg_regs.iter()
                    .filter(|r| tainted.contains(&r.to_string()))
                    .map(|r| r.to_string()).collect();
                if !tainted_args.is_empty() {
                    dangerous_sinks.push(serde_json::json!({
                        "addr": format!("0x{:x}", insn.address()),
                        "target": operands,
                        "tainted_args": tainted_args,
                        "severity": "high",
                        "reason": "Tainted data passed to function call",
                    }));
                }
            },
            "jmp" if parts.len() == 1 => {
                let target = parts[0].to_lowercase();
                if tainted.iter().any(|t| target.contains(&t.to_lowercase())) {
                    dangerous_sinks.push(serde_json::json!({
                        "addr": format!("0x{:x}", insn.address()),
                        "target": operands,
                        "severity": "critical",
                        "reason": "Tainted data used as jump target (potential RCE)",
                    }));
                }
            },
            _ => {}
        }
    }

    Ok(serde_json::json!({
        "taint_log": taint_log,
        "dangerous_sinks": dangerous_sinks,
        "final_tainted_regs": tainted.into_iter().collect::<Vec<_>>(),
        "total_instructions": insns.as_ref().len(),
    }))
}

// 11.3 — Anti-obfuscation Detection
#[tauri::command]
fn detect_obfuscation(hex_bytes: String, arch: String, start_addr: u64) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;
    let bytes = hex::decode(&hex_bytes).map_err(|e| format!("{}", e))?;
    let cs = Capstone::new()
        .x86()
        .mode(if arch == "x64" { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;
    let insns = cs.disasm_all(&bytes, start_addr).map_err(|e| format!("{}", e))?;

    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut nop_count = 0u32;
    let mut jmp_count = 0u32;
    let mut indirect_jmp_count = 0u32;
    let mut xor_string_loops = 0u32;
    let mut opaque_predicates: Vec<serde_json::Value> = Vec::new();
    let total = insns.as_ref().len();

    let mut prev_mnemonic = "";
    let mut prev_operands = "";

    for insn in insns.as_ref().iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");

        // Dead code: nop / nop padding
        if mnemonic == "nop" || (mnemonic == "xchg" && operands.contains("eax") && operands.contains("eax")) {
            nop_count += 1;
        }

        // Control flow flattening indicators: excessive unconditional jumps
        if mnemonic == "jmp" {
            jmp_count += 1;
            if operands.contains('[') || operands.contains("eax") || operands.contains("rax") {
                indirect_jmp_count += 1;
            }
        }

        // XOR string decryption loop pattern
        if mnemonic == "xor" && !operands.is_empty() {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 && parts[0] != parts[1] && (operands.contains('[') || operands.contains("byte")) {
                xor_string_loops += 1;
            }
        }

        // Opaque predicate detection: cmp followed by always-true/always-false jump
        if prev_mnemonic == "cmp" {
            // Pattern: cmp reg, reg followed by je (always true)
            let prev_parts: Vec<&str> = prev_operands.split(',').map(|s| s.trim()).collect();
            if prev_parts.len() == 2 && prev_parts[0] == prev_parts[1] && (mnemonic == "je" || mnemonic == "jz") {
                opaque_predicates.push(serde_json::json!({
                    "addr": format!("0x{:x}", insn.address()),
                    "type": "always_true",
                    "pattern": format!("{} {} ; {}", prev_mnemonic, prev_operands, mnemonic),
                }));
            }
        }

        prev_mnemonic = mnemonic;
        prev_operands = operands;
    }

    // Scoring
    let nop_ratio = if total > 0 { nop_count as f64 / total as f64 } else { 0.0 };
    let jmp_ratio = if total > 0 { jmp_count as f64 / total as f64 } else { 0.0 };

    if nop_ratio > 0.1 {
        findings.push(serde_json::json!({ "type": "dead_code", "severity": "medium", "detail": format!("{:.1}% NOP instructions detected ({} / {})", nop_ratio*100.0, nop_count, total) }));
    }
    if jmp_ratio > 0.15 {
        findings.push(serde_json::json!({ "type": "control_flow_flattening", "severity": "high", "detail": format!("{:.1}% unconditional jumps ({} / {})", jmp_ratio*100.0, jmp_count, total) }));
    }
    if indirect_jmp_count > 3 {
        findings.push(serde_json::json!({ "type": "indirect_jumps", "severity": "high", "detail": format!("{} indirect jump instructions (dispatcher pattern)", indirect_jmp_count) }));
    }
    if xor_string_loops > 2 {
        findings.push(serde_json::json!({ "type": "xor_string_encryption", "severity": "medium", "detail": format!("{} XOR byte operations detected (possible string decryption)", xor_string_loops) }));
    }
    if !opaque_predicates.is_empty() {
        findings.push(serde_json::json!({ "type": "opaque_predicates", "severity": "high", "detail": format!("{} opaque predicate patterns detected", opaque_predicates.len()), "locations": opaque_predicates }));
    }

    let obfuscation_score = (nop_ratio * 20.0 + jmp_ratio * 30.0 + (indirect_jmp_count as f64).min(10.0) * 3.0 + (xor_string_loops as f64).min(10.0) * 2.0 + (opaque_predicates.len() as f64) * 5.0).min(100.0) as u32;

    Ok(serde_json::json!({
        "obfuscation_score": obfuscation_score,
        "findings": findings,
        "stats": {
            "total_instructions": total,
            "nop_count": nop_count,
            "jmp_count": jmp_count,
            "indirect_jmp_count": indirect_jmp_count,
            "xor_operations": xor_string_loops,
            "opaque_predicates": opaque_predicates.len(),
        },
    }))
}

// 11.4 — Shellcode Analysis
#[tauri::command]
fn analyze_shellcode(hex_bytes: String, arch: String) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;
    let bytes = hex::decode(&hex_bytes).map_err(|e| format!("{}", e))?;
    let cs = Capstone::new()
        .x86()
        .mode(if arch == "x64" { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;
    let insns = cs.disasm_all(&bytes, 0).map_err(|e| format!("{}", e))?;

    let mut api_patterns: Vec<serde_json::Value> = Vec::new();
    let mut peb_access = false;
    let mut syscall_found = false;
    let mut position_independent = true;
    let mut stack_strings: Vec<String> = Vec::new();

    let mut disasm: Vec<serde_json::Value> = Vec::new();
    let mut push_sequence: Vec<u8> = Vec::new();

    for insn in insns.as_ref().iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");

        disasm.push(serde_json::json!({
            "addr": format!("0x{:x}", insn.address()),
            "bytes": insn.bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "inst": format!("{} {}", mnemonic, operands),
        }));

        // PEB/TEB access pattern (fs:[0x30] or gs:[0x60])
        if operands.contains("fs:") && operands.contains("0x30") {
            peb_access = true;
            api_patterns.push(serde_json::json!({ "addr": format!("0x{:x}", insn.address()), "type": "PEB_access", "detail": "Accessing PEB via FS:[0x30] (API resolution)" }));
        }
        if operands.contains("gs:") && operands.contains("0x60") {
            peb_access = true;
            api_patterns.push(serde_json::json!({ "addr": format!("0x{:x}", insn.address()), "type": "PEB_access_x64", "detail": "Accessing PEB via GS:[0x60] (x64 API resolution)" }));
        }

        // Syscall instruction
        if mnemonic == "syscall" || mnemonic == "int" && operands.contains("0x2e") {
            syscall_found = true;
            api_patterns.push(serde_json::json!({ "addr": format!("0x{:x}", insn.address()), "type": "syscall", "detail": "Direct syscall detected" }));
        }

        // Absolute address usage = not position independent
        if operands.contains("0x0040") || operands.contains("0x0041") {
            position_independent = false;
        }

        // Stack string construction (push immediate bytes)
        if mnemonic == "push" {
            if let Some(hex_val) = operands.strip_prefix("0x") {
                if let Ok(val) = u32::from_str_radix(hex_val, 16) {
                    for b in val.to_le_bytes() {
                        if b >= 0x20 && b <= 0x7e { push_sequence.push(b); }
                        else if b == 0 && !push_sequence.is_empty() {
                            if push_sequence.len() >= 3 {
                                stack_strings.push(String::from_utf8_lossy(&push_sequence).to_string());
                            }
                            push_sequence.clear();
                        }
                    }
                }
            }
        } else if !push_sequence.is_empty() && mnemonic != "push" {
            if push_sequence.len() >= 3 {
                stack_strings.push(String::from_utf8_lossy(&push_sequence).to_string());
            }
            push_sequence.clear();
        }

        // Known hash values for API resolution (ror13 hash patterns)
        if mnemonic == "cmp" || mnemonic == "mov" {
            let known_hashes = [
                (0x0726774C_u64, "kernel32.dll!LoadLibraryA"),
                (0xEC0E4E8E, "kernel32.dll!GetProcAddress"),
                (0x5FC8D902, "kernel32.dll!VirtualAlloc"),
                (0x876F8B31, "kernel32.dll!WinExec"),
                (0x56A2B5F0, "kernel32.dll!ExitProcess"),
                (0xE553A458, "kernel32.dll!VirtualFree"),
                (0x6174A599, "ws2_32.dll!connect"),
                (0x006B8029, "ws2_32.dll!WSAStartup"),
            ];
            for (hash, name) in &known_hashes {
                if operands.contains(&format!("0x{:x}", hash)) || operands.contains(&format!("0x{:X}", hash)) {
                    api_patterns.push(serde_json::json!({ "addr": format!("0x{:x}", insn.address()), "type": "api_hash", "api": name, "hash": format!("0x{:08X}", hash) }));
                }
            }
        }
    }

    Ok(serde_json::json!({
        "disassembly": disasm,
        "size_bytes": bytes.len(),
        "total_instructions": insns.as_ref().len(),
        "position_independent": position_independent,
        "peb_access": peb_access,
        "syscall_found": syscall_found,
        "api_patterns": api_patterns,
        "stack_strings": stack_strings,
        "arch": arch,
    }))
}

// 11.5 — Binary Diff (compare two hex blobs)
#[tauri::command]
fn binary_diff(hex_a: String, hex_b: String, arch: String) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;
    let bytes_a = hex::decode(&hex_a).map_err(|e| format!("{}", e))?;
    let bytes_b = hex::decode(&hex_b).map_err(|e| format!("{}", e))?;
    let cs = Capstone::new()
        .x86()
        .mode(if arch == "x64" { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;

    let insns_a = cs.disasm_all(&bytes_a, 0).map_err(|e| format!("{}", e))?;
    let insns_b = cs.disasm_all(&bytes_b, 0).map_err(|e| format!("{}", e))?;

    let list_a: Vec<String> = insns_a.as_ref().iter()
        .map(|i| format!("{} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")))
        .collect();
    let list_b: Vec<String> = insns_b.as_ref().iter()
        .map(|i| format!("{} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")))
        .collect();

    let mut diffs: Vec<serde_json::Value> = Vec::new();
    let max_len = list_a.len().max(list_b.len());

    for i in 0..max_len {
        let a = list_a.get(i).map(|s| s.as_str()).unwrap_or("<missing>");
        let b = list_b.get(i).map(|s| s.as_str()).unwrap_or("<missing>");
        if a != b {
            diffs.push(serde_json::json!({
                "index": i,
                "addr_a": insns_a.as_ref().get(i).map(|x| format!("0x{:x}", x.address())).unwrap_or_default(),
                "addr_b": insns_b.as_ref().get(i).map(|x| format!("0x{:x}", x.address())).unwrap_or_default(),
                "inst_a": a,
                "inst_b": b,
            }));
        }
    }

    // Byte-level diff
    let mut byte_diffs: Vec<serde_json::Value> = Vec::new();
    let byte_max = bytes_a.len().max(bytes_b.len());
    for i in 0..byte_max.min(4096) {
        let ba = bytes_a.get(i).copied().unwrap_or(0);
        let bb = bytes_b.get(i).copied().unwrap_or(0);
        if ba != bb {
            byte_diffs.push(serde_json::json!({ "offset": i, "byte_a": format!("{:02X}", ba), "byte_b": format!("{:02X}", bb) }));
        }
    }

    let similarity = if max_len > 0 { ((max_len - diffs.len()) as f64 / max_len as f64 * 100.0) as u32 } else { 100 };

    Ok(serde_json::json!({
        "similarity_pct": similarity,
        "instruction_diffs": diffs,
        "byte_diffs": byte_diffs,
        "total_a": list_a.len(),
        "total_b": list_b.len(),
        "size_a": bytes_a.len(),
        "size_b": bytes_b.len(),
    }))
}

// 11.6 — Type Recovery (stack frame analysis)
#[tauri::command]
fn recover_types(hex_bytes: String, arch: String, start_addr: u64) -> Result<serde_json::Value, String> {
    use capstone::prelude::*;
    let bytes = hex::decode(&hex_bytes).map_err(|e| format!("{}", e))?;
    let cs = Capstone::new()
        .x86()
        .mode(if arch == "x64" { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .map_err(|e| format!("Capstone: {}", e))?;
    let insns = cs.disasm_all(&bytes, start_addr).map_err(|e| format!("{}", e))?;

    let mut stack_vars: Vec<serde_json::Value> = Vec::new();
    let mut vtable_refs: Vec<serde_json::Value> = Vec::new();
    let mut frame_size: i64 = 0;
    let mut known_offsets: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let ptr_size = if arch == "x64" { 8i64 } else { 4i64 };

    for insn in insns.as_ref().iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");

        // Detect frame setup: sub esp/rsp, imm
        if (mnemonic == "sub") && (operands.starts_with("esp") || operands.starts_with("rsp")) {
            let parts_vec: Vec<&str> = operands.split(',').collect();
            if parts_vec.len() == 2 {
                let val_str = parts_vec[1].trim();
                if let Some(hex) = val_str.strip_prefix("0x") {
                    frame_size = i64::from_str_radix(hex, 16).unwrap_or(0);
                } else if let Ok(v) = val_str.parse::<i64>() {
                    frame_size = v;
                }
            }
        }

        // Stack variable access patterns: [ebp-XX] or [rbp-XX]
        let bp_re_patterns = ["ebp - ", "ebp + ", "rbp - ", "rbp + ", "ebp-", "ebp+", "rbp-", "rbp+"];
        for pat in &bp_re_patterns {
            if operands.contains(pat) {
                let is_neg = pat.contains('-');
                let op_str: &str = operands;
                if let Some(offset_part) = op_str.split(pat).nth(1) {
                    let clean: &str = offset_part.split(']').next().unwrap_or("").trim();
                    let offset_val = if let Some(hex) = clean.strip_prefix("0x") {
                        i64::from_str_radix(hex, 16).unwrap_or(0)
                    } else {
                        clean.parse::<i64>().unwrap_or(0)
                    };
                    let actual_offset = if is_neg { -offset_val } else { offset_val };
                    if actual_offset != 0 && !known_offsets.contains(&actual_offset) {
                        known_offsets.insert(actual_offset);
                        let access_size = if operands.contains("dword") { 4 }
                            else if operands.contains("qword") { 8 }
                            else if operands.contains("word") { 2 }
                            else if operands.contains("byte") { 1 }
                            else { ptr_size };
                        let inferred_type = match access_size {
                            1 => "char/uint8_t",
                            2 => "short/uint16_t",
                            4 => if operands.contains("xmm") { "float" } else { "int/uint32_t" },
                            8 => "int64_t/pointer",
                            _ => "unknown",
                        };
                        stack_vars.push(serde_json::json!({
                            "offset": actual_offset,
                            "size": access_size,
                            "inferred_type": inferred_type,
                            "name": format!("var_{:x}", actual_offset.unsigned_abs()),
                            "first_access": format!("0x{:x}", insn.address()),
                        }));
                    }
                }
            }
        }

        // vtable reference: mov reg, [reg] then call [reg+offset]
        if mnemonic == "call" && operands.contains('[') && operands.contains('+') {
            vtable_refs.push(serde_json::json!({
                "addr": format!("0x{:x}", insn.address()),
                "instruction": format!("{} {}", mnemonic, operands),
                "type": "virtual_call",
            }));
        }
    }

    // Sort stack vars by offset
    stack_vars.sort_by_key(|v| v["offset"].as_i64().unwrap_or(0));

    Ok(serde_json::json!({
        "frame_size": frame_size,
        "stack_variables": stack_vars,
        "vtable_references": vtable_refs,
        "ptr_size": ptr_size,
        "arch": arch,
    }))
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 12 — PLATFORM & EKOSİSTEM
// ══════════════════════════════════════════════════════════════════════

// 12.1 — Platform bilgisi (cross-compile desteği)
#[tauri::command]
fn get_platform_info() -> serde_json::Value {
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
        "exe_suffix": std::env::consts::EXE_SUFFIX,
        "dll_suffix": std::env::consts::DLL_SUFFIX,
        "debug_api": if cfg!(target_os = "windows") { "Win32 Debug API" }
                     else if cfg!(target_os = "linux") { "ptrace" }
                     else if cfg!(target_os = "macos") { "mach_vm" }
                     else { "unsupported" },
        "process_api": if cfg!(target_os = "windows") { "ToolHelp32/NtApi" }
                       else if cfg!(target_os = "linux") { "/proc/pid" }
                       else { "sysinfo" },
        "features": {
            "debugger": cfg!(target_os = "windows"),
            "memory_read": cfg!(target_os = "windows"),
            "network_capture": cfg!(target_os = "windows"),
            "pe_analysis": true,
            "disassembly": true,
            "emulation": true,
            "ai": true,
        },
    })
}

// 12.2 — CLI tarama (batch analiz)
#[tauri::command]
fn cli_scan(file_path: String, output_format: String) -> Result<serde_json::Value, String> {
    // Read file
    let data = std::fs::read(&file_path).map_err(|e| format!("Dosya okuma hatası: {}", e))?;
    let file_name = std::path::Path::new(&file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.clone());

    // Basic hashes
    use sha2::Digest;
    let sha256 = format!("{:x}", sha2::Sha256::digest(&data));
    let md5 = format!("{:x}", md5::Md5::digest(&data));
    let sha1 = format!("{:x}", sha1::Sha1::digest(&data));

    let mut result = serde_json::json!({
        "file": file_name,
        "path": file_path,
        "size": data.len(),
        "sha256": sha256,
        "md5": md5,
        "sha1": sha1,
        "format": output_format,
    });

    // Try PE parsing
    if let Ok(pe) = goblin::pe::PE::parse(&data) {
        result["pe"] = serde_json::json!({
            "is_64": pe.is_64,
            "is_dll": pe.is_lib,
            "entry_point": format!("0x{:X}", pe.entry),
            "number_of_sections": pe.sections.len(),
            "imports_count": pe.imports.len(),
            "exports_count": pe.exports.len(),
            "sections": pe.sections.iter().map(|s| {
                let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
                serde_json::json!({
                    "name": name,
                    "virtual_size": s.virtual_size,
                    "virtual_address": format!("0x{:X}", s.virtual_address),
                    "raw_size": s.size_of_raw_data,
                    "characteristics": format!("0x{:X}", s.characteristics),
                })
            }).collect::<Vec<_>>(),
        });
    }

    Ok(result)
}

// 12.3 — Basit script çalıştırma (komut zinciri)
#[tauri::command]
fn run_script(commands: Vec<serde_json::Value>) -> Result<Vec<serde_json::Value>, String> {
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut variables: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();

    for cmd in &commands {
        let action = cmd["action"].as_str().unwrap_or("");
        let step_result = match action {
            "hash" => {
                let path = cmd["path"].as_str().unwrap_or("");
                if let Ok(data) = std::fs::read(path) {
                    use sha2::Digest;
                    let sha256 = format!("{:x}", sha2::Sha256::digest(&data));
                    let r = serde_json::json!({ "ok": true, "sha256": sha256, "size": data.len() });
                    if let Some(var) = cmd["store_as"].as_str() {
                        variables.insert(var.to_string(), r.clone());
                    }
                    r
                } else {
                    serde_json::json!({ "ok": false, "error": "Dosya okunamadı" })
                }
            },
            "disassemble" => {
                let path = cmd["path"].as_str().unwrap_or("");
                let count = cmd["count"].as_u64().unwrap_or(50) as usize;
                if let Ok(data) = std::fs::read(path) {
                    if let Ok(pe) = goblin::pe::PE::parse(&data) {
                        use capstone::prelude::*;
                        let mode = if pe.is_64 { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 };
                        if let Ok(cs) = Capstone::new().x86().mode(mode).syntax(capstone::arch::x86::ArchSyntax::Intel).build() {
                            let ep = pe.entry;
                            let ep_rva = ep as u32;
                            let mut offset = 0usize;
                            for s in &pe.sections {
                                if ep_rva >= s.virtual_address && ep_rva < s.virtual_address + s.virtual_size {
                                    offset = (ep_rva - s.virtual_address + s.pointer_to_raw_data) as usize;
                                    break;
                                }
                            }
                            let end = (offset + count * 15).min(data.len());
                            if let Ok(insns) = cs.disasm_all(&data[offset..end], ep as u64) {
                                let list: Vec<serde_json::Value> = insns.as_ref().iter().take(count).map(|i| {
                                    serde_json::json!({ "addr": format!("0x{:x}", i.address()), "inst": format!("{} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")) })
                                }).collect();
                                let r = serde_json::json!({ "ok": true, "is_64": pe.is_64, "instructions": list });
                                if let Some(var) = cmd["store_as"].as_str() {
                                    variables.insert(var.to_string(), r.clone());
                                }
                                r
                            } else { serde_json::json!({ "ok": false, "error": "Disassembly hatası" }) }
                        } else { serde_json::json!({ "ok": false, "error": "Capstone init hatası" }) }
                    } else { serde_json::json!({ "ok": false, "error": "PE parse hatası" }) }
                } else { serde_json::json!({ "ok": false, "error": "Dosya okunamadı" }) }
            },
            "set_var" => {
                let name = cmd["name"].as_str().unwrap_or("_");
                let value = cmd["value"].clone();
                variables.insert(name.to_string(), value.clone());
                serde_json::json!({ "ok": true, "var": name })
            },
            "get_var" => {
                let name = cmd["name"].as_str().unwrap_or("_");
                variables.get(name).cloned().unwrap_or(serde_json::json!({ "ok": false, "error": "Değişken bulunamadı" }))
            },
            "echo" => {
                let msg = cmd["message"].as_str().unwrap_or("");
                serde_json::json!({ "ok": true, "message": msg })
            },
            _ => serde_json::json!({ "ok": false, "error": format!("Bilinmeyen eylem: {}", action) }),
        };
        results.push(serde_json::json!({ "step": results.len(), "action": action, "result": step_result }));
    }
    Ok(results)
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
            disassemble_at,
            list_functions,
            get_cfg,
            get_xrefs,
            patch_instruction,
            unpack_upx,
            analyze_dump,
            start_gguf_server,
            search_hf_gguf,
            // FAZ 3
            scan_pe_full,
            try_unpack,
            analyze_dump_enhanced,
            extract_pe_from_dump,
            fuzzy_hash,
            fuzzy_compare,
            batch_scan,
            scan_generic,
            // FAZ 8
            list_processes,
            query_memory_regions,
            read_process_memory,
            attach_debugger,
            detach_debugger,
            set_breakpoint,
            get_registers,
            continue_execution,
            disassemble_memory,
            emulate_function,
            get_process_connections,
            // FAZ 10
            fetch_yara_rules,
            fetch_ioc_feed,
            cloud_ai_chat,
            // FAZ 11
            symbolic_execute,
            taint_analysis,
            detect_obfuscation,
            analyze_shellcode,
            binary_diff,
            recover_types,
            // FAZ 12
            get_platform_info,
            cli_scan,
            run_script,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

