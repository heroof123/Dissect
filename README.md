<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-ff6b6b?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Tauri-v2-6366f1?style=for-the-badge&logo=tauri&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/Rust-Backend-e43717?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Local_LLM-22c55e?style=for-the-badge&logo=openai&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" />
</p>

<h1 align="center">🔬 DISSECT v2.0</h1>

<p align="center">
  <strong>Next-Generation Binary Analysis & AI-Powered Reverse Engineering Studio</strong><br/>
  <sub>Tamamen yerel · Verin hiçbir yere gitmez · 12 modül · 12 faz tamamlandı · 40+ Tauri komutu</sub>
</p>

<p align="center">
  <code>Scanner</code> · <code>Hex Patcher</code> · <code>Disassembly</code> · <code>AI Chat</code> · <code>Debugger</code> · <code>Emulation</code> · <code>Network Capture</code> · <code>FLIRT Signatures</code> · <code>Plugin Marketplace</code> · <code>Dashboard</code> · <code>Advanced Analysis</code> · <code>Community Hub</code>
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
Cloud YARA feeds · IOC feed entegrasyonu · tarama paylaşımı
```
- 12 kategoride otomatik string sınıflandırma (URL, Registry, Crypto, IP, Base64...)
- Denuvo, VMProtect, Themida, UPX, ASPack, MPRESS, PECompact, Enigma...
- Risk skoru 0-100 (zararsız → kritik)
- SHA-256, MD5, SHA-1, CRC32, imphash, ssdeep multi-hash
- Bulut YARA kural deposu + IOC feed aboneliği

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
symbolic execution · taint analysis · obfuscation detection · type recovery
```
- Capstone-rs tabanlı tam disassembly
- Fonksiyon keşfi + çağrı grafiği (React Flow + dagre layout)
- Instruction-level XRef: "bu adresi kim çağırıyor?"
- Decompile tahmini (AI destekli pseudo-C)
- **Gelişmiş Analiz Paneli** — 6 sekme: Symbolic Execution, Taint Analysis, Anti-Obfuscation, Shellcode Analysis, Binary Diff, Type Recovery

### 🤖 AI Chat (Local LLM)
```
LM Studio · GGUF Direct · Multi-model · RAG · streaming · bağlam belleği
otomatik rapor · AI agent · bilgi grafiği · fine-tune veri seti
```
- **Explain** — seçili kodu açıkla
- **Analyze** — binary davranış analizi
- **Guide** — tersine mühendislik rehberi
- **Hypothesis** — "bu malware ne yapıyor?" tahmini
- **YARA** — otomatik YARA kural üretimi
- Multi-model desteği (LM Studio + GGUF + Cloud)
- RAG tabanlı bağlamsal arama + bilgi grafiği
- Otomatik analiz raporu oluşturma
- AI agent: otonom çoklu adım analiz

### 🖥️ Process Attach
```
süreç listesi · attach/detach · bellek bölgeleri · hex dump okuyucu
```
- PID, isim, arch, bellek, thread, kullanıcı bilgileri
- .text / .data / heap / DLL / stack bölge haritası
- Adres + boyut bazlı bellek okuma (hex + ASCII)

### 🐛 Debugger
```
step into · step over · run · restart · breakpoint · register view
```
- x86/x64 register görünümü (18 register, EIP/RIP vurgu)
- Hit sayaçlı breakpoint sistemi
- 22 satır senkronize disassembly
- Call stack + debug log (renkli)

### ⚡ Emulation Engine
```
x86 emülatör · register trace · bellek yazma takibi · hız kontrolü
```
- Fonksiyon bazlı emülasyon
- Register değişim vurgulama (changed → sarı)
- Bellek yazma paneli (push/mov/call sonuçları)

### 🌐 Network Capture
```
DNS · TCP · TLS · HTTP · UDP · ICMP · flag sistemi · C2 tespiti
```
- Gerçek süreç bağlantıları (`get_process_connections`)
- **malicious** / **suspicious** / **clean** flag sınıflandırması
- Protokol istatistikleri + paket detay paneli

### 📚 FLIRT Signatures
```
20 imza · 8 kategori · IDA uyumlu · confidence scoring · binary tarama
```
- MSVCRT, WS2_32, ADVAPI32, KERNEL32, NTDLL, CRYPT32, OpenSSL, ZLIB

### 🔬 Advanced Binary Analysis `NEW v2`
```
symbolic execution · taint analysis · anti-obfuscation · shellcode analysis
binary diff · type recovery
```
- **Symbolic Execution** — Path constraint tracking, branch analysis (je/jne/jg/jl)
- **Taint Analysis** — Register taint propagation, dangerous sink detection (RCE, control flow hijack)
- **Anti-Obfuscation** — NOP/JMP ratio, indirect jump, XOR ops, opaque predicates, skor 0-100
- **Shellcode Analysis** — PEB access, syscall detection, API hash matching (ror13), stack string extraction, PIC detection
- **Binary Diff** — Instruction-level + byte-level comparison, similarity percentage
- **Type Recovery** — Stack frame analysis, variable type inference, vtable reference detection

### 🔌 Plugin Marketplace & Community Hub `NEW v2`
```
sandbox execution · marketplace · custom editör · topluluk YARA paylaşımı
plugin export/import · liderlik tablosu
```
- **String Decoder** — Base64/ROT13 otomatik çözümleme
- **Crypto Identifier** — AES/SHA/MD5/Blowfish magic byte tespiti
- **Import Highlighter** — 7 kategori tehlikeli API tespiti
- `DissectPluginAPI`: onScan, registerCommand (Ctrl+K), registerView, accessAI
- Topluluk YARA kural paylaşımı + beğeni sistemi
- Plugin base64 export/import
- Katkıcı liderlik tablosu

### 📊 Dashboard
```
istatistik · risk dağılımı · zaman çizelgesi · packer/DLL frekansı · proje yönetimi
```

### 🎨 UI/UX
- **Komut paleti** (Ctrl+K) — tüm aksiyonlara hızlı erişim
- **Tema editörü** — Özel tema oluştur (4 renk seçici + canlı önizleme)
- **4+ tema** — Dark, Red, Ocean, HighContrast + sınırsız özel tema
- **Onboarding turu** — ilk açılışta rehberli tur
- **Sidebar resize** — sürükle-bırak genişlik
- **i18n** — TR / EN dil desteği
- **PDF rapor** — browser print API ile dışa aktarım
- **Code splitting** — React.lazy + Suspense ile hızlı yükleme
- **Virtual scrolling** — react-window ile büyük veri setlerinde akıcı performans

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────────┐
│                    DISSECT UI                        │
│  React 18 · Vite · Zustand · React Flow · dagre     │
│  React.lazy · react-window · Web Workers             │
├─────────────────────────────────────────────────────┤
│                Tauri v2 IPC Bridge                   │
│              40+ invoke commands                     │
├─────────────────────────────────────────────────────┤
│                   Rust Backend                       │
│  goblin · capstone-rs · sha2 · md5 · sysinfo        │
│  reqwest · tokio · rayon · windows-rs                │
├─────────────────────────────────────────────────────┤
│               Local & Cloud AI Layer                 │
│  LM Studio API · llama-server (GGUF) · Cloud AI     │
└─────────────────────────────────────────────────────┘
```

| Katman | Teknoloji |
|--------|-----------|
| Desktop | **Tauri v2** (Rust + WebView) |
| Frontend | **React 18** + Vite 5 + Zustand |
| Backend | **Rust** (goblin, capstone-rs, sha2, sysinfo, windows-rs) |
| AI | **LM Studio** / llama-server (GGUF) / Cloud AI |
| Graphs | **React Flow** + dagre layout |
| Icons | **Lucide React** |
| Performance | **react-window** + Web Workers + Code Splitting |

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
| **FAZ 7** — Mimari | ✅ Tamamlandı | Code splitting, Zustand, virtual scroll, Web Worker, bundle optimizasyonu |
| **FAZ 8** — Gerçek Backend | ✅ Tamamlandı | Process enum, memory read, debugger, emülasyon, network capture (Rust) |
| **FAZ 9** — AI v2 | ✅ Tamamlandı | Multi-model, RAG, otomatik rapor, AI agent, bilgi grafiği, fine-tune |
| **FAZ 10** — Bulut & İşbirliği | ✅ Tamamlandı | Tarama paylaşımı, takım, bulut YARA/IOC, uzak AI, WebSocket |
| **FAZ 11** — İleri Binary Analiz | ✅ Tamamlandı | Symbolic execution, taint analysis, anti-obfuscation, shellcode, diff, type recovery |
| **FAZ 12** — Platform & Ekosistem | ✅ Tamamlandı | Cross-platform, CLI modu, scripting, tema editörü, topluluk hub |

> Detaylı yol haritası: [ROADMAP.txt](ROADMAP.txt)

---

## 📄 Lisans

MIT — dilediğiniz gibi kullanın, değiştirin, dağıtın.

---

<p align="center">
  <sub>Built with 🔬 by <a href="https://github.com/heroof123">heroof123</a></sub>
</p>
