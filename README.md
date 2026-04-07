<p align="center">
  <img src="https://img.shields.io/badge/Tauri-v2-6366f1?style=for-the-badge&logo=tauri&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/Rust-Backend-e43717?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Local_LLM-22c55e?style=for-the-badge&logo=openai&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" />
</p>

<h1 align="center">🔬 DISSECT</h1>

<p align="center">
  <strong>Next-Generation PE Binary Analysis & AI-Powered Reverse Engineering Studio</strong><br/>
  <sub>Tamamen yerel · Verin hiçbir yere gitmez · 12 modül · 6 faz tamamlandı</sub>
</p>

<p align="center">
  <code>Scanner</code> · <code>Hex Patcher</code> · <code>Disassembly</code> · <code>AI Chat</code> · <code>Debugger</code> · <code>Emulation</code> · <code>Network Capture</code> · <code>FLIRT Signatures</code> · <code>Plugin Marketplace</code> · <code>Dashboard</code>
</p>

---

## 🎯 Ne İşe Yarar?

**DISSECT**, Windows PE binary dosyalarını (`.exe`, `.dll`, `.sys`) kapsamlı analiz eden, yerel AI ile tersine mühendislik yapan ve 12 farklı modülle profesyonel seviyede analiz sunan bir masaüstü stüdyosudur.

> IDA Pro + x64dbg + Wireshark + AI = **DISSECT** — ve tamamen ücretsiz.

---

## ⚡ Modüller

### 🔍 Collector Layer (Scanner)
```
PE32/PE32+ parsing · 30+ packer tespiti · YARA · entropy · risk scoring
imphash · VirusTotal · IOC export (JSON/STIX/CSV) · toplu tarama
```
- 12 kategoride otomatik string sınıflandırma (URL, Registry, Crypto, IP, Base64...)
- Denuvo, VMProtect, Themida, UPX, ASPack, MPRESS, PECompact, Enigma...
- Risk skoru 0-100 (zararsız → kritik)
- SHA-256, MD5, SHA-1, CRC32, imphash multi-hash

### 🔧 Hex Patcher
```
NOP sled · JMP/CALL injection · wildcard pattern · conditional patch script
```
- Önce/sonra hex diff görüntüleme
- PE checksum otomatik güncelleme
- Toplu patch (N dosyaya uygula) + patch import/export (JSON)

### 🧬 Disassembly Engine
```
x86/x64 disassembly · function list · cross-reference (XRef) · CFG graph
```
- Capstone-rs tabanlı tam disassembly
- Fonksiyon keşfi + çağrı grafiği (React Flow + dagre layout)
- Instruction-level XRef: "bu adresi kim çağırıyor?"
- Decompile tahmini (AI destekli pseudo-C)

### 🤖 AI Chat (Local LLM)
```
LM Studio · GGUF Direct · 5 mod · streaming · bağlam belleği
```
- **Explain** — seçili kodu açıkla
- **Analyze** — binary davranış analizi  
- **Guide** — tersine mühendislik rehberi
- **Hypothesis** — "bu malware ne yapıyor?" tahmini
- **YARA** — otomatik YARA kural üretimi
- Son 3 taramayı otomatik bağlam olarak kullanır

### 🖥️ Process Attach `NEW`
```
süreç listesi · attach/detach · bellek bölgeleri · hex dump okuyucu
```
- PID, isim, arch, bellek, thread, kullanıcı bilgileri
- .text / .data / heap / DLL / stack bölge haritası
- Adres + boyut bazlı bellek okuma (hex + ASCII)

### 🐛 Debugger `NEW`
```
step into · step over · run · restart · breakpoint · register view
```
- x86/x64 register görünümü (18 register, EIP/RIP vurgu)
- Hit sayaçlı breakpoint sistemi
- 22 satır senkronize disassembly
- Call stack + debug log (renkli)

### ⚡ Emulation Engine `NEW`
```
x86 emülatör · register trace · bellek yazma takibi · hız kontrolü
```
- Fonksiyon bazlı 12 adım emülasyon
- Register değişim vurgulama (changed → sarı)
- Bellek yazma paneli (push/mov/call sonuçları)
- Unicorn Engine API hazırlığı

### 🌐 Network Capture `NEW`
```
DNS · TCP · TLS · HTTP · UDP · ICMP · flag sistemi · C2 tespiti
```
- Gerçekçi C2 senaryosu: DNS → TLS handshake → beacon → stage2 download
- **malicious** / **suspicious** / **clean** flag sınıflandırması
- Protokol istatistikleri + paket detay paneli

### 📚 FLIRT Signatures `NEW`
```
20 imza · 8 kategori · IDA uyumlu · confidence scoring · binary tarama
```
- MSVCRT, WS2_32, ADVAPI32, KERNEL32, NTDLL, CRYPT32, OpenSSL, ZLIB
- CRT · Network · Registry · FileIO · Memory · Process · Crypto · Compression

### 🔌 Plugin Marketplace
```
sandbox execution · marketplace · 3 hazır plugin · custom plugin editörü
```
- **String Decoder** — Base64/ROT13 otomatik çözümleme
- **Crypto Identifier** — AES/SHA/MD5/Blowfish magic byte tespiti
- **Import Highlighter** — 7 kategori tehlikeli API tespiti
- `DissectPluginAPI`: onScan, registerCommand (Ctrl+K), registerView, accessAI

### 📊 Dashboard
```
istatistik · risk dağılımı · zaman çizelgesi · packer/DLL frekansı · proje yönetimi
```

### 🎨 UI/UX
- **Komut paleti** (Ctrl+K) — tüm aksiyonlara hızlı erişim
- **4 tema** — Dark, Red, Ocean, HighContrast
- **Onboarding turu** — ilk açılışta rehberli tur
- **Sidebar resize** — sürükle-bırak genişlik
- **i18n** — TR / EN dil desteği
- **PDF rapor** — browser print API ile dışa aktarım

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────┐
│                   DISSECT UI                     │
│  React 18 · Vite · Lucide · React Flow · dagre │
├─────────────────────────────────────────────────┤
│               Tauri v2 IPC Bridge               │
├─────────────────────────────────────────────────┤
│                  Rust Backend                    │
│  goblin (PE) · capstone-rs (x86/x64) · YARA    │
│  sha2 · md5 · crc32 · ssdeep · serde           │
├─────────────────────────────────────────────────┤
│               Local AI Layer                     │
│  LM Studio API · llama-server (GGUF)            │
└─────────────────────────────────────────────────┘
```

| Katman | Teknoloji |
|--------|-----------|
| Desktop | **Tauri v2** (Rust + WebView) |
| Frontend | **React 18** + Vite 5 |
| Backend | **Rust** (goblin, capstone-rs, sha2, serde) |
| AI | **LM Studio** / llama-server (GGUF) |
| Graphs | **React Flow** + dagre layout |
| Icons | **Lucide React** |

---

## 🚀 Kurulum

```bash
# 1. Repo'yu klonla
git clone https://github.com/heroof123/Dissect.git
cd Dissect

# 2. Bağımlılıkları yükle
npm install

# 3. Geliştirme modunda çalıştır
npm run tauri dev

# 4. Üretim derlemesi (Windows .exe)
npm run tauri build
```

### Gereksinimler

| Araç | Minimum |
|------|---------|
| [Node.js](https://nodejs.org/) | 18+ |
| [Rust](https://rustup.rs/) | stable |
| [LM Studio](https://lmstudio.ai/) | v0.2+ (AI Chat için) |
| Windows | 10/11 (x64) |

---

## 📈 Geliştirme Durumu

| Faz | Durum | İçerik |
|-----|-------|--------|
| **FAZ 1** — Disassembly | ✅ Tamamlandı | x86/x64 disassembly, fonksiyon listesi, CFG grafiği, XRef, decompile |
| **FAZ 2** — AI Genişletme | ✅ Tamamlandı | Bağlamsal bellek, hex açıklama, IOC çıkarımı, AI diff, decompile, YARA wizard |
| **FAZ 3** — Altyapı | ✅ Tamamlandı | PE Rust parse, packer unpack, similarity hash, ssdeep, paralel tarama, ELF/Mach-O |
| **FAZ 4** — Profesyonel | ✅ Tamamlandı | PDF rapor, binary diff, dashboard, proje, toplu tarama, i18n |
| **FAZ 5** — Plugin | ✅ Tamamlandı | Marketplace, sandbox API, 3 hazır plugin, custom editör |
| **FAZ 6** — İleri Analiz | ✅ Tamamlandı | Process attach, debugger, emülasyon, network capture, FLIRT |

> Detaylı yol haritası: [ROADMAP.txt](ROADMAP.txt) · Özellik listesi: [FEATURES.md](FEATURES.md)

---

## 📄 Lisans

MIT — dilediğiniz gibi kullanın, değiştirin, dağıtın.

---

<p align="center">
  <sub>Built with 🔬 by <a href="https://github.com/heroof123">heroof123</a></sub>
</p>
