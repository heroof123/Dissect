<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-ff6b6b?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/Tauri-v2-6366f1?style=for-the-badge&logo=tauri&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/Rust-Backend-e43717?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Local_LLM-22c55e?style=for-the-badge&logo=openai&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Windows_10%2F11-0078d4?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" />
</p>

<h1 align="center">🔬 DISSECT v2.0</h1>

<p align="center">
  <strong>Yeni Nesil Binary Analiz & AI Destekli Tersine Mühendislik Stüdyosu</strong><br/>
  <sub>Tamamen yerel çalışır · Veriniz hiçbir yere gitmez · 20+ modül · 100+ Tauri komutu · Sıfır bulut bağımlılığı</sub>
</p>

<p align="center">
  <a href="#-ai-chat--yerel-llm-motoru">🤖 AI Chat</a> ·
  <a href="#-system--models">🖥️ System & Models</a> ·
  <a href="#-collector-layer-scanner">🔍 Scanner</a> ·
  <a href="#-hex-patcher">🔧 Hex Patcher</a> ·
  <a href="#-disassembly-engine">🧬 Disassembly</a> ·
  <a href="#-debugger">🐛 Debugger</a> ·
  <a href="#-emulation-engine">⚡ Emulation</a> ·
  <a href="#-platform--ekosistem">🌍 Platform</a> ·
  <a href="#-ayarlar--ui">⚙️ Ayarlar</a>
</p>

---

## 🎯 DISSECT Nedir?

**DISSECT**, Windows PE binary dosyalarını (`.exe`, `.dll`, `.sys`) — ve ELF, APK, Mach-O dahil diğer formatları — derinlemesine analiz eden, **tamamen yerel** çalışan bir masaüstü tersine mühendislik stüdyosudur.

Profesyonel RE araçlarının pahalı, ağır ya da ayrı ayrı olduğu gerçeğinden hareketle tasarlandı:

> **IDA Pro** + **x64dbg** + **Wireshark** + **Yerel AI** = 🔬 **DISSECT** — Ücretsiz, hızlı, gizli.

Verileriniz asla bir sunucuya gönderilmez. Tüm analiz, yapay zeka çıkarımı ve hashing işlemleri bilgisayarınızın kendi RAM ve CPU'sunda gerçekleşir.

---

## ✨ Öne Çıkan Özellikler

| | Özellik | Açıklama |
|---|---|---|
| 🤖 | **Yerel AI Chat** | LM Studio/GGUF modelinizle binary analizi — hiçbir şey buluta gitmiyor |
| 🧬 | **Tam Disassembly** | Capstone tabanlı x86/x64, fonksiyon listesi, CFG grafiği, XRef |
| 🔍 | **Derin PE Scanner** | 30+ packer tespiti, YARA, entropy, risk skoru, IOC export |
| 🐛 | **Canlı Debugger** | Breakpoint, step-into/over, register dump, call stack |
| ⚡ | **x86 Emülatör** | Unicorn tabanlı; kodu çalıştırmadan kodu anlayın |
| 🌐 | **Network Capture** | DNS / TCP / TLS / HTTP paketi yakalama + C2 tespiti |
| 🔌 | **Plugin Marketplace** | Kendi JS plugin'inizin yazdığınız sandbox'lı ortam |
| 📋 | **Rapor Motoru** | STIX / JSON / HTML / PDF — tek tuşla analiz raporu |
| 🌍 | **Çoklu Platform** | ELF, APK, Mach-O, PE32/PE32+ — hepsi tek pencerede |
| 🎨 | **Tam Özelleştirme** | Tema editörü, i18n, erişilebilirlik, resizable layout |

---

## 🤖 AI Chat — Yerel LLM Motoru

> **Kısaca:** Binary analizi için özelleştirilmiş, internet bağlantısı gerektirmeyen yapay zeka asistanı.

AI Chat sekmesi sıradan bir sohbet botu değil. Scanner veya Disassembly'den gelen ham veriyi (import tablosu, entropy, disassembly çıktısı, hex dump) doğrudan konuşmaya taşıyıp modele bağlam olarak gönderebildiğiniz, **bağlamsal bir analiz motoru**dur.

### Nasıl Çalışır?

```
Siz → "Bu fonksiyon ne yapıyor?"
   ↓
Dissect → [Assembly kodu] + [Import tablosu] + [Entropy] → LLM'e gönderir
   ↓
Model → İnsan diline çevrilmiş teknik analiz
```

Modele internet üzerinden ulaşılmaz. LM Studio ya da GGUF loader aracılığıyla tamamen yerel çalışır.

### 6 Konuşma Modu

| Mod | Ne Yapar? |
|-----|-----------|
| 🔍 **Explain** | Seçtiğiniz assembly bloğunu veya hex verisini düz İngilizce / Türkçe anlatır |
| 🧠 **Analyze** | Binary'nin genel davranışını (startup, anti-debug, network, persistence) inceler |
| 📖 **Guide** | "Bu malware'i nasıl analiz ederim?" gibi adım adım rehber sunar |
| 💡 **Hypothesis** | "Bu binary ne amaçla yazılmış olabilir?" sorusunu yanıtlar |
| 📜 **YARA Wizard** | Otomatik YARA tespit kuralı üretir — kopyala, çalıştır |
| 🤖 **AI Agent** | Otonom çok adımlı analiz: tarar → disassemble eder → raporlar |

### Scanner'dan AI'ya Tek Tıkla

Scanner sayfasında bir dosyayı taradıktan sonra **"Send to AI"** düğmesine basın. Tüm analiz sonucu (hash, packer, imports, strings, entropy, risk skoru) otomatik olarak AI Chat'e aktarılır ve bağlam olarak eklenir.

### Desteklenen Model Kaynakları

```
LM Studio  →  http://localhost:1234/v1/chat/completions
GGUF       →  Doğrudan llama.cpp sunucusu veya yerel loader
Cloud AI   →  İsteğe bağlı OpenAI-uyumlu endpoint (kendi API key'inizle)
```

### RAG (Retrieval-Augmented Generation)

AI Chat, analiz geçmişinizdeki verileri SQLite'a indeksler. "Geçen hafta incelediğim RAT'ta bu API var mıydı?" sorusunu yanıtlayabilir çünkü önceki taramaları hatırlar.

---

## 🖥️ System & Models

> **Kısaca:** Bilgisayarınızın donanımını tanıyan, hangi AI modelini kullanabileceğinizi söyleyen ve model yönetimini tek yerden yapan kontrol merkezi.

### GPU & CUDA Dedektörü

Açıldığında arka planda sisteminizi tararaktoplar:

| Bilgi | Ne İşe Yarar? |
|-------|---------------|
| GPU adı + VRAM | Hangi model boyutunu çalıştırabileceğinizi gösterir |
| CUDA sürümü | GPU offload (LLM hızlandırma) destekli mi? |
| RAM + CPU çekirdeği | CPU-only modellerin hız tahmini için |
| DirectX / Vulkan | Gelecek GPU tabanlı çıkarım için hazırlık |

Örnek: 8 GB VRAM varsa 7B-Q4 model sorunsuz çalışır. VRAM yoksa CPU-only 3B-Q4 önerilir.

### HuggingFace Model Arama

Doğrudan arayüzden HuggingFace API'ye bağlanarak tersine mühendislik veya güvenlik odaklı modelleri arayabilirsiniz:

```
Aranan: "malware analysis llm"
        ↓
Sonuçlar: Model adı · Boyut · Lisans · İndirme sayısı · Download linki
```

### Yerel Model Yöneticisi

- İndirilen GGUF modellerini listeler (dosya boyutu, format, kuantizasyon seviyesi)
- Aktif modeli değiştirme — AI Chat anında yeni modeli kullanmaya başlar
- Benchmark: seçili modelle test sorgusu çalıştırıp token/sn ölçer
- Önerilen modeller (donanımınıza göre filtrelenmiş)

### Model Uyumluluk Tablosu (Otomatik Hesaplanır)

```
VRAM: 8 GB   RAM: 32 GB
─────────────────────────────────────────────────
✅ Mistral 7B Q4_K_M      — Önerilen
✅ CodeLlama 7B Q4        — Kod analizi için
⚠️ Mixtral 8x7B Q3       — Yavaş, denenebilir
❌ LLaMA-3 70B Q4         — Yetersiz bellek
```

---

## 🔍 Collector Layer (Scanner)

> Binary'yi sürükle bırak, her şeyi otomatik öğren.

- **PE32 / PE32+ / ELF / Mach-O** parsing (goblin-rs ile Rust'ta)
- **30+ Packer Tespiti**: UPX, Denuvo, VMProtect, Themida, Enigma, ASPack, MPRESS…
- **Entropy Grafiği**: Yüksek entropi → şifreli/paketlenmiş bölge anlamına gelir
- **Risk Skoru 0–100**: Zararsız → Düşük → Orta → Yüksek → Kritik
- **Multi-Hash**: SHA-256, MD5, SHA-1, CRC32, imphash, ssdeep (fuzzy)
- **YARA Taraması**: 50+ yerleşik kural + bulut kural deposu
- **IOC Export**: JSON, STIX 2.1, CSV — SIEM'e hazır
- **Toplu Tarama**: Klasör veya ZIP içindeki tüm dosyaları paralel tara
- **String Sınıflandırma**: 12 kategori — URL, IP, Registry, Crypto, Base64, PowerShell…

---

## 🔧 Hex Patcher

> Assembly bilmeden binary'yi değiştirin.

- Ham hex düzenleyici: offset + yeni bytes gir, kaydet
- **NOP Sled**: seçili aralığı 0x90 ile doldur (patch atlama koşulları)
- **JMP / CALL Injection**: adrese atlama koduyla patch
- **Pattern Search**: wildcard destekli byte pattern arama (`90 ?? FF 15`)
- Önce/sonra diff görünümü — ne değişti net belli
- PE checksum otomatik yeniden hesaplama
- Patch import/export (JSON) — aynı patch'i binlerce dosyaya uygula

---

## 🧬 Disassembly Engine

> Exe'yi aç, içindeki kodu okuyun.

- **Capstone-rs** tabanlı x86 / x64 tam disassembly
- Otomatik **fonksiyon sınırı tespiti** + fonksiyon listesi (ada veya adrese göre arama)
- **XRef (Cross-Reference)**: "Bu adres kim tarafından çağrılıyor?"
- **CFG Grafiği**: Kontrol akış diyagramı (React Flow + dagre layout) — her blok, her dallanma görünür
- **AI Decompile**: Seçili fonksiyonu sözde-C koduna çevir (AI ile)
- **Gelişmiş Analiz Paneli** — 6 alt sekme:

| Sekme | Açıklama |
|-------|----------|
| Symbolic Execution | Dallanma kısıtlarını sembolik olarak takip et |
| Taint Analysis | Kontrol akışını etkileyen "kirlenmiş" değerleri izle |
| Anti-Obfuscation | NOP/JMP oranı, dolaylı jump, XOR sayımı, skor 0-100 |
| Shellcode Analysis | PEB erişimi, syscall, API hash (ror13) tespiti |
| Binary Diff | İki dosya ya da iki fonksiyon arasında instruction karşılaştırma |
| Type Recovery | Stack frame değişken türü tahmini, vtable referansı |

---

## 🐛 Debugger

> Çalışan bir süreci adım adım izleyin.

- **Process Attach**: Çalışan herhangi bir Windows sürecine bağlan (PID ile)
- Breakpoint ekle / kaldır — hit sayaçlı
- **Step Into / Step Over / Continue / Restart**
- 18 register canlı görünümü (EAX–EIP, FLAGS, SSE)
- 22 satır senkronize disassembly (EIP'in etrafı)
- Call stack + debug event log (exception, module load, thread)
- Watch expressions: register veya bellek adresini sürekli izle

---

## ⚡ Emulation Engine

> Kodu çalıştırmadan "çalış" — sandboxsuz, güvenli.

Unicorn tabanlı x86 emülatör. Kötü amaçlı kodu gerçek sisteminizi etkilemeden emüle eder.

- Fonksiyon bazlı emülasyon başlatma
- Register değişimlerini vurgular (değişen → sarı)
- Memory write tracker: hangi adrese ne yazıldı?
- Hız kontrolü (adım adım vs. tam hız)

---

## 🌐 Network Capture

> Sürecin ne ile konuştuğunu görün.

- **`get_process_connections`** ile gerçek Windows bağlantılarını listeler
- DNS, TCP, TLS, HTTP, UDP, ICMP paket görünümü
- Otomatik sınıflandırma: `malicious` / `suspicious` / `clean`
- **C2 Beacon Tespiti**: periyodik bağlantı deseni tanıma
- Paket detay paneli + protokol istatistikleri
- NetworkCapture → SandboxPage entegrasyonu: aynı session'ın ağ loglarını Sandbox'ta görün

---

## 📚 FLIRT Signatures

> "Bu fonksiyon hangi kütüphaneden?" — saniyeler içinde yanıt.

- 20+ yerleşik imza, 8 kütüphane kategorisi (MSVCRT, WS2_32, OpenSSL, ZLIB…)
- IDA Pro uyumlu `.sig` / `.pat` dosyası import etme
- Confidence scoring — eşleşme ne kadar kesin?
- AI destekli isim önerisi: bulunamayan fonksiyonlar için heuristic tahmin

---

## 🔬 String Analizi

> Şifreli veya kodlanmış stringler artık sır değil.

- XOR brute-force (1-255 key aralığı)
- Base64 / ROT13 / Hex / URL encode otomatik çözme
- Stack string yeniden yapılandırma
- AI destekli string açıklama: "Bu string ne anlama gelir?"

---

## ⚖️ BinDiff

> İki binary arasındaki farkı bulun — patch analizi, versiyonlar arası karşılaştırma.

- Import tablosu farkı (eklenen / kaldırılan API)
- Export farkı
- Section bazlı karşılaştırma (boyut, entropi, isim)
- Instruction-level inline diff
- HTML diff raporu export et (renkli, paylaşılabilir)
- Benzerlik yüzdesi hesaplama

---

## 🕵️ API Tracing

> Programın hangi Windows API'lerini çağırdığına bakın.

- IAT (Import Address Table) tam dump
- 7 kategori tehlikeli API tespiti: memory injection, persistence, network, anti-debug, crypto, file, process
- Risk bazlı renklendirme
- API'nin ne işe yaradığını AI ile açıklat

---

## 🛡️ Anti-Analysis Dedektörü

> "Bu binary kendini analiz edilmekten koruyor mu?"

- **Anti-Debug Tespiti**: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInfo
- **VM Tespiti**: VMware/VirtualBox CPUID, registry, bellek tuzakları
- **Sandbox Bypass**: sleep-loop, WMI sorgusu, pencere sayısı kontrolü
- **Packer Fingerprinting**: 30+ packer imzası
- Tespit edilen her teknik için bypass önerisi (AI destekli)

---

## 📦 Sandbox

> Dosyayı çalıştırın, ne yaptığına bakın — sisteminiz etkilenmesin.

- Kısıtlı çalıştırma ortamı
- Davranış logu: dosya erişimi, registry, process creation, network
- `sandbox_record_network` ile ağ olaylarını kaydet
- NetworkCapture sayfasıyla entegre: sandbox session'ının ağ trafiği oradan görünür

---

## 📋 Rapor Üretimi

> Analiz sonucunu tek tuşla paylaşılabilir rapora dönüştür.

- **HTML Rapor**: Renkli, okunabilir, tarayıcıda açılır
- **PDF Export**: Tarayıcı print API — kurumsal raporlamaya hazır
- **IOC Bundle**: JSON / STIX 2.1 / CSV — SIEM, EDR entegrasyonu için
- **Rapor Geçmişi**: Önceki raporları kaydet, karşılaştır
- **D3 Diff Raporu**: İki raporu yan yana getirip "ne değişti" göster

---

## 🧠 Bilgi Tabanı

> Tekrar eden soruları bir daha araştırmayın.

- **RAG (Retrieval-Augmented Generation)**: Geçmiş analiz notları + teknik belgelerden cevap üret
- **MITRE ATT&CK Entegrasyonu**: Tespit edilen teknikler otomatik MITRE ID ile eşlenir
- **SQLite indeksleme**: Tüm geçmiş taramalar aranabilir
- Kendi notlarınızı ekleyin: hash, teknik not, şüphe kaydı

---

## 🌍 Platform & Ekosistem

> Sadece Windows PE değil — her platformun binary'si.

| Format | Neler Analiz Edilir? |
|--------|---------------------|
| **ELF** (Linux) | Section, segment, dynamic linking, GOT/PLT |
| **APK** (Android) | Manifest, izinler, DEX hash, şüpheli API |
| **Mach-O** (macOS) | Fat binary, linked libs, entropi, load commands |
| **PE32/PE32+** | Tam destek — tüm özellikler |

### Script Engine (Monaco Editör)

Kendi analiz scriptlerinizi yazın:

```bash
format:          → dosya formatını yazdır
entropy:         → entropy değerini yazdır
strings: 6       → min 6 karakter stringleri listele
risk:            → risk skorunu göster
```

- Monaco Editor tabanlı (VS Code'un aynı editörü)
- Syntax highlighting + autocomplete
- Script kaydet, isimlendir, tekrar çalıştır

### Batch Tarama

Klasör veya ZIP — tüm dosyaları sıraya al, paralel tara, tek rapor al.

### CLI / CI/CD Modu

```bash
dissect-cli analyze malware.exe --format json --output report.json
# exit code: 0 = temiz, 1 = yüksek risk
# GitHub Actions, GitLab CI, Jenkins ile doğrudan entegrasyon
```

---

## 🔌 Plugin Marketplace

> Dissect'i kendinize göre genişletin.

- **Sandbox'lı JS Plugin Ortamı**: Güvenli API erişimi, sisteme zarar veremez
- **`DissectPluginAPI`**: `onScan`, `registerCommand`, `registerView`, `accessAI`
- Hazır pluginler: String Decoder, Crypto Identifier, Import Highlighter, YARA Scanner Pro…
- Kendi plugin'inizi Ctrl+K komut paletine entegre edin
- Plugin base64 export/import — takımınızla paylaşın
- **Remote Marketplace**: 8 topluluk plugin'i doğrudan yükleyin

---

## 📊 Dashboard

> Tüm analiz geçmişinizi bir bakışta görün.

- Risk dağılımı pasta grafiği
- Zaman bazlı tarama istatistikleri
- En sık karşılaşılan packer/DLL frekansı
- Proje yönetimi: dosyaları gruplara ayırın, notlar ekleyin
- Takım workspace: birlikte analiz, yorum, atama

---

## ⚙️ Ayarlar & UI

### Tema Sistemi

- 4 yerleşik tema: **Dark**, **Red**, **Ocean**, **High Contrast**
- **Sınırsız özel tema**: 4 renk seçici + canlı önizleme + kaydet
- Temayı başlık çubuğundan tek tıkla değiştir

### Hex Editor Pro

- **Bookmark Sistemi**: Offset'lere isim ve renk ver ("MZ başlığı", "şüpheli xor döngüsü")
- **Binary Template**: Struct overlay — DOS_HEADER, IMAGE_FILE_HEADER, ELF_HEADER otomatik alan haritası
- Virtual scroll: 1 GB+ dosyada bile akıcı kaydırma

### i18n & Erişilebilirlik

- TR / EN / DE / FR / ES / ZH / JA / KO + daha fazlası
- High contrast modu
- Font büyüklüğü ayarı (0.8× — 1.4×)
- Screen reader uyumlu ARIA etiketleri
- `reduce_motion` — animasyon kısaltma

### Layout & Pencere

- Sidebar genişliği sürükle-bırak ile ayarla
- Pencere boyutu hatırlama (kapandığında kaydedilir)
- **Çoklu monitör Pop-out**: Herhangi bir paneli ikinci monitöre al
- Ctrl+Tekerlek ile %70 — %150 arası zoom

### Komut Paleti (Ctrl+K)

Her özelliğe klavyeden ulaşın. Ctrl+1–6 ile sekmeler arası geçiş.

---

## 🏗️ Mimari

```
┌──────────────────────────────────────────────────────────────┐
│                        DISSECT UI                            │
│    React 18 · Vite 5 · Zustand · React Flow · dagre          │
│    React.lazy (code-split) · react-window · Web Workers      │
│    Monaco Editor · Lucide Icons                               │
├──────────────────────────────────────────────────────────────┤
│                    Tauri v2 IPC Bridge                        │
│                  100+ invoke commands                         │
├──────────────────────────────────────────────────────────────┤
│                      Rust Backend                            │
│  goblin · capstone-rs · sha2 · md5 · sysinfo · reqwest       │
│  tokio · rayon · windows-rs · rusqlite · hex                  │
│  unicorn · bindgen (capstone FFI)                             │
├──────────────────────────────────────────────────────────────┤
│               Local & Optional Cloud AI Layer                 │
│     LM Studio API · llama.cpp (GGUF) · OpenAI-compat.        │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Kurulum

### Gereksinimler

| Araç | Sürüm | Notlar |
|------|-------|--------|
| [Node.js](https://nodejs.org/) | 18+ | Frontend build için |
| [Rust](https://rustup.rs/) | stable | Backend derleme için |
| [LM Studio](https://lmstudio.ai/) | v0.2+ | AI Chat için (isteğe bağlı) |
| Windows | 10 / 11 x64 | Zorunlu |

### Adımlar

```bash
# 1. Repo'yu klonla
git clone https://github.com/heroof123/Dissect.git
cd Dissect

# 2. Bağımlılıkları yükle
npm install

# 3. Geliştirme modunda çalıştır (hot-reload)
npm run tauri dev

# 4. Üretim derlemesi (.exe installer)
npm run tauri build
```

### AI Chat için LM Studio Kurulumu

1. [lmstudio.ai](https://lmstudio.ai/) adresinden LM Studio'yu kurun
2. Bir model indirin (öneri: `mistral-7b-instruct-v0.2.Q4_K_M.gguf`)
3. LM Studio → **Local Server** → **Start Server** (port 1234)
4. Dissect → AI Chat → model endpoint otomatik algılanır

---

## 📈 Tamamlanmış Fazlar

| Faz | İçerik |
|-----|--------|
| **A** | Debugger, Process Attach, Network, FLIRT, Sandbox gerçek entegrasyon |
| **B** | String analizi, RTTI, PE resource/certificate, BinDiff, AI renaming |
| **C** | API Tracing, Sandbox, Anti-Analysis, Network entegrasyonu |
| **D** | Dashboard, Rapor motoru, geçmiş, karşılaştırma |
| **E** | ELF/Mach-O/APK, CLI modu, Monaco script, plugin marketplace, takım workspace |
| **F** | Hex bookmark/template, i18n, erişilebilirlik, virtual scroll, bellek profil |

> Detaylı yol haritası: [ROADMAP.txt](ROADMAP.txt)

---

## 📄 Lisans

MIT — dilediğiniz gibi kullanın, değiştirin, dağıtın.

---

<p align="center">
  <sub>Built with 🔬 by <a href="https://github.com/heroof123">heroof123</a></sub><br/>
  <sub><i>Verileriniz burada kalır. Her zaman.</i></sub>
</p>

