# DISSECT

> PE Binary Analysis · AI-Powered Reverse Engineering · Hex Patcher

<p align="center">
  <strong>Yerleşik AI destekli masaüstü binary analiz aracı</strong><br/>
  Tauri v2 · React · Rust · Capstone · LM Studio / GGUF
</p>

---

## Nedir?

**DISSECT**, PE (Portable Executable) dosyalarını detaylı şekilde analiz eden, yerel AI modelleriyle tersine mühendislik yapan ve hex düzenleme imkanı sunan bir masaüstü uygulamasıdır. Tamamen yerel çalışır — verileriniz hiçbir yere gönderilmez.

## Özellikler

### 🔍 Scanner
- PE32/PE32+ tam ayrıştırma (header, section, import, export, resource)
- 12 kategoride otomatik string sınıflandırma
- 30+ packer & koruma tespiti (Denuvo, VMProtect, Themida, UPX...)
- 30+ dahili YARA kuralı
- Entropy analizi + interaktif grafik
- Multi-hash (MD5, SHA-1, SHA-256, CRC32, imphash)
- Risk skorlama (0-100)
- VirusTotal entegrasyonu
- Toplu tarama & klasör tarama
- JSON, STIX 2.1, CSV IOC dışa aktarım

### 🔧 Patcher
- NOP sled üreticisi & JMP/CALL enjeksiyonu
- Wildcard pattern arama
- Koşullu patch scripti
- Toplu patch (N dosyaya uygula)
- Önce/Sonra hex karşılaştırma
- PE checksum otomatik güncelleme
- Patch import/export (JSON)

### 🤖 AI Chat
- **LM Studio** veya **GGUF Direct** (llama-server) ile yerel LLM bağlantısı
- 5 AI modu: Explain, Analyze, Guide, Hypothesis, YARA
- Scanner sonuçlarını AI'a otomatik aktarma
- Streaming yanıt, sohbet dışa aktarımı, özetleme

### ⚙️ System
- GPU/CUDA tespiti + kurulum sihirbazı
- HuggingFace GGUF model arama & indirme
- Yerel model yönetimi

### 🎨 UI/UX
- Komut paleti (Ctrl+K)
- 4 tema (Dark, Red, Ocean, HighContrast)
- Onboarding turu
- Klavye kısayolları

## Teknoloji

| Katman | Teknoloji |
|--------|-----------|
| Desktop Framework | Tauri v2 |
| Frontend | React + Vite |
| Backend | Rust |
| PE Parsing | goblin |
| Disassembly | capstone-rs (x86/x64) |
| AI | LM Studio API / llama-server (GGUF) |

## Kurulum

```bash
# Bağımlılıkları yükle
npm install

# Geliştirme modunda çalıştır
npm run tauri dev

# Üretim derlemesi
npm run tauri build
```

### Gereksinimler
- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) toolchain
- [LM Studio](https://lmstudio.ai/) veya [llama.cpp](https://github.com/ggerganov/llama.cpp) (AI Chat için)

## Yol Haritası

Geliştirme planı için [ROADMAP.txt](ROADMAP.txt), tamamlanan özelliklerin detayı için [FEATURES.md](FEATURES.md) dosyasına bakın.

## Lisans

MIT
