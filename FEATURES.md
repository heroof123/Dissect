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

## 🦀 Rust Backend — 17 Tauri Komutu

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
| `parse_pe_rust(file_path)` | Tam PE parsing (goblin) |
| `file_hash(file_path)` | SHA-256 hash |
| `multi_hash(file_path)` | MD5 + SHA-1 + SHA-256 + CRC32 |
| `disassemble_ep(file_path, count)` | Capstone x86/x64 EP disassembly |
| `apply_patches(file_path, patches)` | Hex patch uygula + checksum |
| `read_hex_region(file_path, offset, len)` | Hex bölge oku (max 256 byte) |
| `unpack_upx(file_path)` | UPX decompression |
| `analyze_dump(file_path)` | Ham binary entropy + PE imza + string |
| `ai_analyze(json, model, url)` | Ollama streaming (eski) |

---

## 🔌 Plugin Sistemi (Temel)

- **Hook arayüzü tanımlı:** `onScan(result)`, `onPatch(file)`, `renderPanel()`
- **API dökümantasyonu** — kod örneğiyle birlikte
- **Dahili plugin listesi** — örnek plugin şablonları

---

*Bu dosya projenin mevcut durumunu belgelemektedir. Geliştirme planı için [ROADMAP.txt](ROADMAP.txt) dosyasına bakın.*
