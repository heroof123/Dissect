# DISSECT — Özellik Listesi (Features)

> Binary Analysis · AI Reverse Engineering · Hex Patcher  
> Son güncelleme: 2026-04-07

---

## 🔍 Scanner — PE Analiz Motoru

- **PE32/PE32+ header parsing** — goblin (Rust) ile tam PE ayrıştırma
- **Entry point, image base, timestamp** — DLL/EXE tespiti, sahte timestamp uyarısı
- **Section tablosu** — isim, virtual address, raw/virtual boyut, entropy, RWX bayraklar
- **Import tablosu** — DLL grupları, fonksiyon listesi, delayed import tespiti, imphash
- **Export tablosu** — isim + adres vektörü çıkarımı
- **Resource çıkarımı** — ikon, manifest, versiyon bilgisi, string tablosu
- **String çıkarımı & sınıflandırma** — ASCII + UTF-16LE, 12 otomatik kategori:
  - URL, IP, Path, Registry, Anti-Debug, Anti-VM, Protection, Crypto, Network, Mutex, Injection, Ransomware
- **Entropy analizi** — section bazlı + genel dosya entropisi + interaktif grafik (7.2+ eşik)
- **Multi-hash** — MD5, SHA-1, SHA-256, CRC32, imphash, Rich Header hash
- **Koruma tespiti** — Denuvo DRM, VMProtect, Themida, Anti-Debug, Anti-VM
- **Packer tespiti** — 30+ bilinen packer (section isim + entropy + signature kombinasyonu)
- **YARA kuralları** — 30+ dahili kural, otomatik eşleştirme
- **TLS callback tespiti** — `.tls` section tarama
- **Exception directory** — `.pdata` (x64 SEH) fonksiyon tablosu sayımı
- **Debug bilgisi** — PDB yolu + GUID çıkarımı (RSDS signature)
- **Risk skorlama** — 0-100 kompozit skor (Clean / Moderate / High Risk)
- **Overlay tespiti** — boyut ölçümü + uyarı
- **Tarama profilleri** — Hızlı (EP+koruma+hash), Derin (tüm section+string+IOC), Adli (tam analiz)
- **Çoklu dosya toplu tarama** — batch scanning + klasör tarama (.exe/.dll/.sys/.ocx/.scr/.cpl filtre)
- **İki dosya karşılaştırma** — hex diff (ilk 512 byte) + section entropy karşılaştırma
- **Tarama geçmişi** — localStorage, max 100 kayıt, arama + yıldızlama + not ekleme
- **VirusTotal entegrasyonu** — SHA-256 hash sorgusu (API anahtarıyla)
- **Dışa aktarım** — JSON rapor, STIX 2.1 bundle, CSV IOC, toplu HTML rapor

---

## 🔧 Patcher — Hex Düzenleme Motoru

- **Tek/çoklu patch uygulama** — offset + hex değer ile doğrudan yazma
- **NOP sled üreticisi** — uzunluk belirle, 0x90 dizisi oluştur
- **JMP/CALL enjeksiyonu** — hedef adres gir, E9/E8 + relative offset otomatik hesapla
- **Pattern arama** — wildcard hex pattern (0xFF = joker), sonuçtan tıkla-patch
- **Hex viewer** — byte yoğunluk çubuğu ile görsel bölge gösterimi
- **Patch doğrulama** — yazılan byte'ları geri oku, beklenenle karşılaştır
- **Koşullu patch scripti** — `if {byte@offset}==X then patch Y` sözdizimi
- **Toplu patch** — etkin patch setini birden fazla dosyaya uygula
- **Önce/Sonra hex gösterimi** — iki sütunlu karşılaştırma
- **Patch import/export** — JSON formatında kaydet/yükle
- **Otomatik yedekleme** — `.bak` dosyası oluşturma
- **PE checksum yeniden hesaplama** — patch sonrası otomatik güncelleme
- **Patch toggle** — etkinleştir/devre dışı bırak (uygulamadan hariç tut)

---

## 🤖 AI Chat — Yerel LLM Entegrasyonu

- **LM Studio modu** — OpenAI-uyumlu API (localhost:1234), API key desteği, model seçimi
- **GGUF Direct modu** — llama-server otomatik başlatma, port yapılandırma, health check
- **5 AI modu:**
  - 🧠 **Explain** — PE binary eğitim amaçlı açıklama
  - 🔬 **Analyze** — güvenlik analizi, packer/anti-debug/anomali
  - 📘 **Guide** — adım adım tersine mühendislik rehberi
  - 💡 **Hypothesis** — binary hakkında 3 farklı hipotez üretimi
  - 🛡 **YARA** — bulgulara göre YARA kuralı üretimi
- **Streaming yanıt** — gerçek zamanlı metin akışı (`chat-chunk` / `chat-done` event'ları)
- **Scanner → Chat veri aktarımı** — tarama sonuçları JSON olarak chat input'a preload
- **Sohbet dışa aktarımı** — HTML ve Markdown formatında
- **Sohbet özetleme** — 3-5 maddelik otomatik özet
- **9 hızlı komut butonu** — mod bazlı önceden tanımlı prompt'lar
- **Takip önerileri** — mod bazlı follow-up butonları
- **Bağlamsal bellek (Context Memory)** — son N tarama özetini otomatik system prompt'a ekle, bellek yönetimi paneli, temizle/max limit ayarla
- **Hex aralığı AI açıklama** — Hex viewer'da "AI'a Sor" butonu, seçili baytlar + offset bilgisiyle AI'a gönder, struct tahmini
- **Fonksiyon decompile** — Disassembly'den seçili fonksiyonu AI'a gönder, C/C++ pseudocode üretimi, sağ tık menüsü + araç çubuğu butonu
- **Çoklu bağlam sistemi (Multi-Context Tray)** — birden fazla veri kaynağını (scanner, patcher, hex, disasm) aynı anda seçip AI'a gönder, tümünü seç/hiçbiri/temizle, chip tabanlı toggle UI
- **Çoklu dosya AI karşılaştırması** — 2+ scanner/PE sonucu seçili iken "Karşılaştır" butonu, section/import/entropy/risk otomatik kıyaslama
- **Otomatik IOC çıkarımı** — AI yanıtlarından IP/domain/MD5/SHA1/SHA256/URL/dosya yolu/registry key otomatik parse, tablo görünümü, tek tıkla YARA kuralına dönüştür, IOC kopyala
- **AI güven skoru** — her yanıta %0-100 kesinlik derecesi, renk kodlu badge (yeşil/sarı/kırmızı), "Yüksek olasılıkla" / "Orta kesinlik" / "Düşük güven" etiketleri
- **YARA kural sihirbazı** — AI destekli otomatik kural üretimi, kural adı belirle, elle düzenle, kural kütüphanesi (kaydet/yükle/sil), bağlam kaynaklarından akıllı kural oluşturma

---

## ⚙️ System — Donanım & Model Yönetimi

- **Sistem bilgisi** — CPU marka/model, çekirdek sayısı, RAM (GB), OS sürümü
- **GPU tespiti** — NVIDIA (nvidia-smi), AMD/Intel (WMIC)
- **CUDA sürüm tespiti** — `nvcc --version` veya `nvidia-smi` sorgusu
- **CUDA kurulum sihirbazı** — 5 adımlı rehber + bağlantılar
- **Yerel model tarama** — GGUF/bin dosyalarını listele
- **Model indirme** — URL ile indirme, MB/toplam MB ilerleme çubuğu
- **HuggingFace arama** — GGUF model arama API (beğeniye göre sıralı, top 10)

---

## 🎨 UI/UX

- **Komut paleti** — `Ctrl+K` ile her özelliğe hızlı erişim + geçmiş dosyalar
- **Onboarding turu** — ilk açılışta 5 adımlı interaktif rehber
- **4 tema** — Dark, Red, Ocean, HighContrast (erişilebilirlik)
- **Yakınlaştırma** — `Ctrl+Scroll`, 0.7x-1.5x, kalıcı kayıt
- **Yeniden boyutlandırılabilir kenar çubuğu** — sürüklenebilir ayraç
- **Klavye kısayolları** — `Ctrl+1-5` sayfa geçişi, `Ctrl+K` komut paleti, `Escape` kapat
- **Pencere boyutu hafızası** — son boyut kaydedilir
- **İşletim sistemi bildirimleri** — tarama tamamlandığında OS notification

---

## 🦀 Rust Backend — 25+ Tauri Komutu

| Komut | İşlev |
|-------|-------|
| `get_system_info()` | CPU, çekirdek, RAM, GPU (nvidia-smi + wmic) |
| `list_models(dir)` | Dizindeki GGUF/bin dosyalarını listele |
| `download_model(url, dest)` | İlerleme event'lı model indirme |
| `get_cuda_version()` | CUDA toolkit sürüm sorgusu |
| `start_gguf_server(path, port)` | llama-server sürecini başlat |
| `search_hf_gguf(query)` | HuggingFace GGUF model arama |
| `lms_list_models(url, key)` | LM Studio model listesi |
| `lms_chat_stream(msgs, model, url, key)` | Streaming chat yanıtı |
| `scan_pe_full(file_path)` | **FAZ 3.1** — Tam PE analiz (strings, imports, exports, hashing, packer, YARA, risk, Rich header, .NET, code caves, WRX, resources) |
| `scan_generic(file_path)` | **FAZ 3.6** — Otomatik format tespiti (PE/ELF/Mach-O) |
| `try_unpack(file_path)` | **FAZ 3.2** — Multi-packer unpack (UPX/ASPack/MPRESS/PECompact/Petite) |
| `analyze_dump_enhanced(file_path)` | **FAZ 3.3** — MDMP parsing, embedded PE, memory regions, PE extraction |
| `extract_pe_from_dump(dump, offset, out)` | **FAZ 3.3** — Dump'tan PE çıkarımı |
| `fuzzy_hash(file_path)` | **FAZ 3.4** — CTPH fuzzy hashing (ssdeep-style) |
| `fuzzy_compare(hash1, hash2)` | **FAZ 3.4** — İki fuzzy hash benzerlik karşılaştırması (0-100) |
| `batch_scan(file_paths)` | **FAZ 3.5** — Rayon paralel toplu tarama + progress event |
| `file_hash(file_path)` | SHA-256 hash |
| `multi_hash(file_path)` | MD5 + SHA-1 + SHA-256 + CRC32 |
| `disassemble_ep(file_path, count)` | Capstone x86/x64 EP disassembly |
| `apply_patches(file_path, patches)` | Hex patch uygula + checksum |
| `read_hex_region(file_path, offset, len)` | Hex bölge oku (max 256 byte) |
| `unpack_upx(file_path)` | UPX decompression (legacy) |
| `analyze_dump(file_path)` | Ham binary entropy + PE imza + string (legacy) |
| `ai_analyze(json, model, url)` | Ollama streaming (eski) |

### FAZ 3 — Rust Backend Güçlendirme

- **Tam PE parsing Rust'a taşındı** — `scan_pe_full` komutu tüm JS `analyzePE()` fonksiyonunu karşılıyor
  - String çıkarımı (ASCII + UTF-16LE, 14 kategori sınıflandırması)
  - Packer tespiti (9 section-name + 4 EP-byte signature)
  - Multi-hash (MD5/SHA1/SHA256/CRC32/imphash)
  - YARA-like kural değerlendirmesi (20+ kural, severity seviyeleri)
  - Risk skorlama (aynı ağırlıklı formül)
  - Rich header, overlay, .NET CLR, code caves, WRX sections, packing ratios
  - Delayed imports, debug PDB, EP bytes, resource tablosu
- **Multi-packer unpack** — `try_unpack` komutu UPX dışında 8 packer daha destekler
  - Otomatik UPX decompression + entropy-based packed section tespiti
  - Başarısız durumda packer-spesifik öneriler
- **Enhanced dump analysis** — `analyze_dump_enhanced` komutu
  - Windows Minidump (MDMP) header parsing + stream directory
  - Embedded PE image tespiti ve boyut tahminlemesi
  - Memory region sınıflandırma (entropy tabanlı: sparse/structured/code/compressed/encrypted)
  - PE extraction: `extract_pe_from_dump` ile dump'tan PE çıkarımı
- **Fuzzy hashing** — CTPH implementasyonu (ssdeep uyumlu format)
  - Context-triggered piecewise hashing (auto block-size scaling)
  - Hash karşılaştırma: LCS tabanlı similarity (0-100 skor)
- **Paralel batch scanning** — Rayon thread pool
  - `batch_scan` komutu: tüm dosyaları eşzamanlı analiz
  - `batch-progress` event: dosya bazlı ilerleme (done/total/pct)
  - Frontend otomatik olarak Rust batch scanner kullanır
- **ELF / Mach-O desteği** — `scan_generic` komutu
  - ELF: sections, dynamic symbols, shared libraries, PIE/stripped detection
  - Mach-O: segments, load commands, linked libraries (Fat binary desteği)
  - Otomatik format tespiti (goblin multi-format parser)

---

## 🔌 Plugin Ekosistemi (FAZ 5)

### 5.1 Plugin Yükleyici
- **Dosya sistemi yükleme** — `.js` dosya picker ile plugin yükleme
- **Plugin manifest** — id, name, version, author, desc, tags, code
- **Sandbox execution** — `new Function()` ile izole ortam (sadece `Dissect` API + `console`)
- **Custom plugin editörü** — textarea ile doğrudan kod yazma ve kurma
- **Persist** — `localStorage` ile kurulu plugin'ler kalıcı

### 5.2 Plugin Mağazası UI
- **Marketplace** — 3 hazır plugin: String Decoder, Crypto Identifier, Import Highlighter
- **Kur / Kaldır** — tek tıkla install/uninstall
- **ON/OFF toggle** — plugin'i devre dışı bırakma/etkinleştirme
- **Yıldız derecelendirme** — 1-5 arası, localStorage'da saklanır
- **Arama** — isim + etiket filtresi
- **İndirme sayısı** — marketplace'de gösterilir

### 5.3 Plugin API (DissectPluginAPI)
- **`onScan(fn)`** — tarama sonrası otomatik hook (addToHistory'den fire edilir)
- **`onPatch(fn)`** — hex patch uygulandığında tetiklenir
- **`onDisassemble(fn)`** — disassembly analiz hook'u
- **`registerCommand(label, fn)`** — Ctrl+K komut paletine özel komut ekleme
- **`registerView(id, label, renderFn)`** — özel panel kaydı
- **`accessAI(prompt)`** — AI'a prompt gönderme
- **`log(...args)`** — güvenli konsol çıktısı (`[Plugin:id]` prefix)
- **`getHistory()`** — tarama geçmişine salt-okunur erişim
- **API dökümantasyon tab'ı** — tam referans ve örnekler

### 5.4 Örnek Plugin'ler
- **String Decoder** — Base64/ROT13 encoded string tespit ve çözümleme
- **Crypto Identifier** — AES, SHA-256, MD5, Blowfish, CRC32, TEA magic byte tespiti + CNG/CryptoAPI DLL tespiti
- **Import Highlighter** — 7 kategori tehlikeli API tespiti (Injection, Execution, Persistence, Anti-Debug, Network, Crypto, File System)

---

## 📊 Dashboard & İstatistikler (FAZ 4.3)

- **DashboardPage** — `VIEWS.DASHBOARD` ile erişilebilir yeni sayfa
- **StatCard bileşeni** — toplam tarama, high/moderate/clean risk, avg risk, x64/x86 dağılımı
- **Zaman çizelgesi** — son 14 günlük tarama aktivitesi bar chart
- **Koruma dağılımı** — Denuvo, VMProtect, Themida, AntiDebug, AntiVM horizontal bar
- **Packer dağılımı** — en sık 8 packer horizontal bar chart
- **DLL frekansı** — en sık 10 DLL horizontal bar chart
- **Sidebar NavItem** — BarChart2 ikonlu, "NEW" badge

## 📄 PDF Rapor Dışa Aktarımı (FAZ 4.1)

- **Browser Print API** — styled HTML → `window.print()` ile PDF oluşturma
- **Kapak sayfası** — Dissect logosu, tarih, dosya sayısı, ortalama risk
- **İstatistik blokları** — total scans, high/moderate/clean, x64/x86
- **Packer & DLL dağılımı tabloları** — inline tablo formatında
- **Detaylı sonuç tablosu** — dosya adı, arch, risk, packers, SHA-256, tarih
- **Alt bilgi** — Dissect versiyon + ISO timestamp

## 🔀 Gelişmiş Binary Diff (FAZ 4.2)

- **2048 byte hex diff** — 512'den genişletildi
- **Diff region tespiti** — contiguous fark bölgeleri sayımı
- **Heatmap şerit** — 200px mini strip, farklar kırmızı
- **Import diff** — DLL bazlı: eklenen (yeşil) / silinen (kırmızı) + common sayısı
- **String diff** — ilk 20 eklenen/silinen string karşılaştırması
- **Diff özet çubuğu** — changed bytes, unchanged bytes, regions, size diff
- **Size diff** — dosya boyutu farkı hesaplama

## 🔎 Gelişmiş Arama & Filtreler (FAZ 4.4)

- **Regex toggle** — normal metin veya regex ile arama
- **Dosya adı / hash / packer arama** — SHA-256, MD5, packer ismi
- **Mimari filtresi** — x64, x86, tümü
- **Risk filtresi** — High (60+), Moderate (30-59), Clean (<30)
- **Packer filtresi** — dinamik packer listesi dropdown
- **Tarih aralığı** — from/to date picker
- **Sonuç tablosu** — dosya, arch, risk, packers, SHA-256, tarih sütunları

## 📁 Workspace / Proje (FAZ 4.5)

- **Proje oluşturma** — isim + otomatik ID + timestamp
- **Proje silme** — inline silme butonu
- **Projeye ekleme** — filtrelenmiş sonuçları projeye toplu ekleme
- **Proje filtresi** — aktif proje seçildiğinde sadece o projenin dosyaları
- **Proje JSON export** — proje metadata + tüm tarama verileri

## 🌐 i18n Yerelleştirme Altyapısı (FAZ 4.6)

- **LANGS sözlüğü** — TR + EN locale string'leri
- **useLang() hook** — `lang`, `setLang()`, `t` accessor
- **localStorage** — `dissect_lang` key ile dil tercihi saklanması
- **Hazır key'ler** — scanner, patcher, disasm, chat, system, plugins, dashboard, risk, search, filter, export, report, projects, create, delete, noData vb.

---

## 🖥️ Process Attach — Canlı Süreç Bağlanma (FAZ 6.1)

- **Süreç listesi** — PID, isim, arch (x86/x64), bellek, thread, kullanıcı sütunları
- **Sıralama + arama** — tüm sütunlarda sıralama, PID/isim filtresi
- **Attach / Detach** — tek tıkla bağlanma, yeşil durum göstergesi
- **Bellek bölgeleri** — 12 bölge: PE Header, .text, .rdata, .data, .rsrc, .reloc, Heap, Stack, DLL, SharedData
- **Bellek okuma** — hex dump görüntüleyici (adres + hex + ASCII), adres/boyut girişi
- **Hızlı bölge seçimi** — .text / .data / Heap butonları ile otomatik adres doldurma
- **Süreç detayları** — 8 alan grid kartı (PID, isim, arch, bellek, thread, modül, parent, user)

## 🐛 Debugger Entegrasyonu (FAZ 6.2)

- **Step Into / Step Over / Run / Restart** — 4 kontrol butonu
- **x86 / x64 register** — geçiş yapılabilir, 18 register (RIP/EIP vurgusu)
- **Disassembly görünümü** — 22 satır, mevcut satır vurgulama, breakpoint noktaları
- **Breakpoint sistemi** — adres bazlı ekleme/kaldırma/toggle, hit sayacı
- **Call stack** — 8 frame, return address + info
- **Debug log** — renkli çıktı: break (kırmızı), step (mor), run (yeşil)
- **Breakpoint'ten tıkla** — disassembly satırına tıklayarak BP toggle

## ⚡ Emülasyon Motoru (FAZ 6.3)

- **12 adım emülasyon** — sub_4012C0 fonksiyonunun tam emülasyonu
- **Run All / Step / Reset** — 3 kontrol + hız slider (50-1000ms)
- **Register değişim takibi** — değişen register sarı vurgu
- **Bellek yazma paneli** — adres, değer, açıklama (push/mov/call sonuçları)
- **Execution log** — tamamlanan talimatlar listesi
- **Emülasyon trace** — ilerleme göstergeli satır vurgulama (✓/▸)
- **Unicorn Engine API** — gelecek entegrasyon için altyapı hazır

## 🌐 Network Capture — Ağ Trafiği Yakalama (FAZ 6.4)

- **15 paket sandbox capture** — DNS, TCP, TLS, HTTP, UDP, ICMP protokolleri
- **Gerçekçi C2 senaryosu** — DNS lookup → TLS handshake → beacon POST → stage2 download → heartbeat
- **Flag sistemi** — malicious (kırmızı), suspicious (sarı), clean (yeşil)
- **İstatistik paneli** — toplam paket, flag dağılımı, protokol sayıları, toplam boyut
- **Arama + filtre** — IP, protokol, içerik bazlı arama + flag filtreleme
- **Paket detay** — tıkla ve genişletilmiş bilgi gör (proto, size, src/dst, data, flag, time)
- **Capture Start/Stop** — simüle yakalama kontrolü

## 📚 FLIRT İmza Veritabanı (FAZ 6.5)

- **20 imza** — MSVCRT (5), WS2_32 (4), ADVAPI32 (2), KERNEL32 (4), NTDLL (1), CRYPT32 (1), OpenSSL (1), ZLIB (1)
- **8 kategori** — CRT, Network, Registry, FileIO, Memory, Process, Crypto, Compression
- **Kategori filtresi** — tek tıkla kategori seçimi
- **Arama** — fonksiyon, kütüphane veya açıklama bazlı
- **Confidence bar** — %75-98 arası güven skoru (yeşil/sarı/kırmızı)
- **Binary'de Ara** — simüle eşleşme taraması
- **Eşleşme sonuçları** — adres + fonksiyon + kütüphane + kategori + match skoru tablosu

---

*Bu dosya projenin mevcut durumunu belgelemektedir. Geliştirme planı için [ROADMAP.txt](ROADMAP.txt) dosyasına bakın.*
