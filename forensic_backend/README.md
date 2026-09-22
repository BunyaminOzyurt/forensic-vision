# 🛡️ Forensic Vision - Siber Güvenlik, Dosya Adli Bilişimi & Raporlama (Aşama 2)

Forensic Vision projesinin 2. Aşaması; dosya bütünlüğü doğrulama (Magic Bytes), EXIF ve GPS metadata analizi, dosya oyma (File Carving / Binwalk mantığı), kriptografik özetleme (Hashing & Tehdit İstihbaratı), resmi ReportLab PDF raporlaması ve FastAPI / Streamlit servislerini içerir.

---

## 📁 Klasör Mimarisi

```text
forensic_backend/
│
├── forensics/
│   ├── __init__.py
│   ├── magic_bytes.py      # Magic Bytes (File Header) & Uzantı Doğrulama (Spoofing Tespiti)
│   ├── exif_parser.py      # EXIF Metadata, GPS Çözümleme & Manipülasyon İzi (Photoshop/GIMP)
│   ├── file_carver.py      # Dosya sonuna gömülü veri / ZIP tespiti (Binwalk & Entropi)
│   └── hash_lookup.py      # MD5, SHA-1, SHA-256 Hashing & Zararlı İtibar Kontrolü
│
├── reports/
│   ├── __init__.py
│   └── pdf_generator.py    # ReportLab ile Resmi Adli Bilişim PDF Raporu Motoru
│
├── main.py                 # FastAPI REST API Sunucusu (/api/v1/analyze, /api/v1/report)
├── app.py                  # Streamlit Web Arayüzü (Dashboard)
├── test_backend.py         # Uçtan Uca Otomatik Test Betiği
├── requirements.txt        # Gerekli kütüphaneler
├── Dockerfile              # Docker konteyner yapılandırması
├── docker-compose.yml      # Multi-servis konteyner orkestrasyonu
└── README.md
```

---

## 🚀 Hızlı Başlangıç

### 1. Bağımlılıkların Kurulması

```bash
cd forensic_backend
pip install -r requirements.txt
```

### 2. Testleri Çalıştırma

Tüm adli bilişim modüllerini, PDF oluşturucuyu ve FastAPI sunucu uç noktalarını otomatik doğrulamak için:

```bash
python test_backend.py
```

### 3. FastAPI REST Sunucusunu Başlatma

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
- **API Dokümantasyonu (Swagger UI):** `http://127.0.0.1:8000/docs`
- **ReDoc Dokümantasyonu:** `http://127.0.0.1:8000/redoc`

### 4. Streamlit Dashboard'u Başlatma

```bash
streamlit run app.py
```
- Tarayıcınızda açılan adreste (`http://localhost:8501`) dosyayı sürükleyip bırakabilir, canlı tehdit skorlarını, EXIF haritasını inceleyebilir ve resmi PDF raporunu indirebilirsiniz.

---

## 🐳 Docker ile Çalıştırma

Tüm sistemi tek komutla ayağa kaldırmak için:

```bash
docker compose up --build
```
- **FastAPI:** `http://localhost:8000`
- **Streamlit:** `http://localhost:8501`

---

## 📡 REST API Uç Noktaları

| Metot | Uç Nokta | Açıklama |
|---|---|---|
| `GET` | `/` | API karşılama ve modül durumları |
| `GET` | `/api/v1/health` | Sistem sağlık ve depolama durumu |
| `POST` | `/api/v1/analyze` | Dosya yükleme ve adli bilişim analizini başlatma (JSON yanıt) |
| `GET` | `/api/v1/report/{analysis_id}` | Üretilen resmi adli bilişim PDF raporunu indirme |
| `GET` | `/api/v1/analyses` | Tamamlanan son adli analiz oturumları |

---

## 🔒 Güvenlik & Adli Bilişim Standartları

- **Magic Bytes Doğrulama:** Dosya uzantısının (.jpg, .png vb.) gerçek dosya başlığı ile uyumlu olup olmadığını doğrular, uzantı yanıltması (Spoofing) saldırılarını yakalar.
- **EXIF & GPS Analizi:** Çekim donanımı, tarih, GPS koordinatları ve Photoshop/GIMP gibi düzenleme yazılım izlerini tespit eder.
- **File Carving & Entropi:** EOF (End-of-File) sınırından sonra iliştirilmiş verileri, şifrelenmiş taşıyıcı yükleri ve gömülü ZIP/RAR/PE arşivlerini ortaya çıkarır.
- **Kriptografik Bütünlük (Chain of Custody):** MD5, SHA-1 ve SHA-256 değerleriyle delil bütünlüğünü garanti eder.
- **Resmi PDF Raporlama:** T.C. adli bilişim ve ISO/IEC 27037 dijital delil standartlarına uygun resmi PDF formatı üretir.
