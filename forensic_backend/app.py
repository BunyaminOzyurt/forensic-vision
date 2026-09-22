"""
Forensic Vision - Streamlit Adli Bilişim & Siber Güvenlik Web Paneli (Dashboard)
Sürükle-bırak dosya yükleme, EXIF haritası, Güvenlik İhlal Skorları,
Isı Haritaları görselleştirmesi ve tek tıkla Adli Bilişim PDF Raporu indirme imkanı sunar.
"""

import os
import sys
import time
import uuid
import tempfile
import requests
import streamlit as st
import pandas as pd

# Sayfa yapılandırması
st.set_page_config(
    page_title="Forensic Vision - Adli Bilişim Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Üst dizin ve modül yolları
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Yerel modülleri içe aktar (Doğrudan çalışma desteği için)
from forensics.magic_bytes import verify_file_integrity
from forensics.exif_parser import extract_exif
from forensics.file_carver import detect_appended_payload
from forensics.hash_lookup import calculate_hashes
from reports.pdf_generator import generate_forensic_pdf
from forensics.deepfake_analyzer import analyze_deepfake_heuristic

# CV Motoru Kontrolü
CV_AVAILABLE = False
cv_engine = None
try:
    from cv_engine import ForensicCVEngine
    cv_engine = ForensicCVEngine(default_output_dir=os.path.join(CURRENT_DIR, "outputs"))
    CV_AVAILABLE = True
except Exception:
    CV_AVAILABLE = False

# Özel CSS ile Modern Siber Güvenlik Teması
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-clean {
        background-color: #DCFCE7;
        color: #166534;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("Forensic Vision")
    st.caption("v2.0 - Siber Güvenlik & Dijital Delil Motoru")
    st.markdown("---")

    backend_mode = st.radio(
        "Çalışma Modu:",
        ["Doğrudan Modül (Yerel)", "FastAPI REST API"],
        help="FastAPI arka planında veya doğrudan Python modülleriyle analiz gerçekleştirin."
    )

    api_url = "http://127.0.0.1:8000"
    if backend_mode == "FastAPI REST API":
        api_url = st.text_input("API URL:", value="http://127.0.0.1:8000")
        try:
            r = requests.get(f"{api_url}/api/v1/health", timeout=1.5)
            if r.status_code == 200:
                st.success("🟢 FastAPI Sunucusu Bağlı")
            else:
                st.warning("🟠 API Yanıt Verdi Ancak Hata Kodu Döndü")
        except Exception:
            st.error("🔴 FastAPI Sunucusuna Ulaşılamıyor (Yerel Mod Kullanılıyor)")

    st.markdown("---")
    st.subheader("İnceleme Bilgileri")
    case_id = st.text_input("Vaka / Dosya No:", value="VAKA-2026-0922")
    examiner_name = st.text_input("Adli Bilişim Uzmanı:", value="Forensic Analyst")

    st.markdown("---")
    st.markdown("### Modül Durumları")
    st.markdown("✅ Magic Bytes & Uzantı Doğrulama")
    st.markdown("✅ EXIF & GPS Parser")
    st.markdown("✅ File Carver (Binwalk EOF)")
    st.markdown("✅ Hash & Tehdit Veritabanı")
    st.markdown("✅ ReportLab PDF Motoru")
    st.markdown("✅ CV ELA/FFT/Deepfake" if CV_AVAILABLE else "⚠️ CV Motoru (Torch/CV Opsiyonel)")

# ----------------- ANA PANEL -----------------
st.markdown("<div class='main-header'>🛡️ Forensic Vision - Adli Bilişim & Görüntü Doğrulama</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-header'>Dosya Bütünlüğü, Magic Bytes, EXIF Metadata, File Carving & AI Tabanlı Anomali Tespiti</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "İncelenecek Delil Dosyasını Sürükleyip Bırakın veya Seçin:",
    type=None,
    help="JPEG, PNG, GIF, WEBP, PDF, ZIP, EXE veya herhangi bir şüpheli ikili dosya yükleyebilirsiniz."
)


def run_local_analysis(file_bytes: bytes, filename: str) -> dict:
    """
    FastAPI olmadan doğrudan yerel modülleri kullanarak analizi yürütür.
    """
    analysis_id = uuid.uuid4().hex[:12]
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, f"{analysis_id}_{filename}")

    with open(temp_file_path, "wb") as f:
        f.write(file_bytes)

    magic_res = verify_file_integrity(temp_file_path)
    hashes_res = calculate_hashes(temp_file_path)
    exif_res = extract_exif(temp_file_path)
    carver_res = detect_appended_payload(temp_file_path)

    cv_res = {
        "status": "skipped",
        "deepfake_probability": 0.0,
        "entropy_score": 0.0,
        "is_stego_suspect": False,
        "ela_image_path": None,
        "fft_spectrum_path": None,
        "bit_planes_path": None
    }

    is_image = any(filename.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"])

    if CV_AVAILABLE and is_image:
        try:
            cv_out_dir = os.path.join(CURRENT_DIR, "outputs")
            os.makedirs(cv_out_dir, exist_ok=True)
            raw_cv = cv_engine.analyze_media(temp_file_path, output_dir=cv_out_dir)
            if raw_cv.get("status") == "success":
                cv_res = raw_cv
        except Exception as e:
            cv_res["error"] = str(e)

    # CV motoru yoksa → Heuristic ELA+FFT+DCT+Entropi+EXIF analizi
    if not CV_AVAILABLE and is_image:
        try:
            heuristic = analyze_deepfake_heuristic(temp_file_path)
            if heuristic.get("status") == "success":
                cv_res = {
                    "status": "heuristic",
                    "deepfake_probability": heuristic.get("deepfake_probability", 0.0),
                    "entropy_score": heuristic.get("entropy_score", 0.0),
                    "is_stego_suspect": heuristic.get("is_stego_suspect", False),
                    "verdict": heuristic.get("verdict", "NORMAL"),
                    "fired_techniques": heuristic.get("fired_techniques", 0),
                    "confidence_score": heuristic.get("confidence_score", 0.0),
                    "indicators": heuristic.get("indicators", []),
                    "technique_results": heuristic.get("technique_results", {}),
                    "ela_image_path": None,
                    "fft_spectrum_path": None,
                    "bit_planes_path": None
                }
        except Exception as e:
            cv_res["heuristic_error"] = str(e)

    # Tehdit Skoru Hesapla
    score = 0
    if magic_res.get("spoof_detected"):
        score += 40
    if carver_res.get("payload_detected"):
        score += 45
    elif carver_res.get("has_appended_data"):
        score += 25
    if hashes_res.get("reputation", {}).get("is_known_malicious"):
        score += 50
    if exif_res.get("software_tampering_suspect"):
        score += 20
    if cv_res.get("deepfake_probability", 0) > 0.6:
        score += 30
    if cv_res.get("is_stego_suspect"):
        score += 25
    score = min(max(score, 0), 100)

    threat_level = "CRITICAL" if score >= 70 else ("SUSPICIOUS" if score >= 35 else "CLEAN")

    # PDF Raporunu Oluştur
    reports_dir = os.path.join(CURRENT_DIR, "reports_generated")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f"forensic_report_{analysis_id}.pdf")

    report_data = {
        "analysis_id": analysis_id,
        "file_name": filename,
        "magic_bytes": magic_res,
        "hashes": hashes_res,
        "exif": exif_res,
        "file_carver": carver_res,
        "cv_analysis": cv_res,
        "threat_assessment": {
            "security_score": score,
            "threat_level": threat_level
        }
    }

    try:
        generate_forensic_pdf(report_data, pdf_path)
    except Exception as e:
        pdf_path = None

    report_data["pdf_path"] = pdf_path
    return report_data


if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name

    st.info(f"📁 Yüklenen Dosya: **{filename}** ({len(file_bytes):,} Bytes)")

    if st.button("🚀 Kapsamlı Adli Bilişim Analizini Başlat", type="primary"):
        with st.spinner("Adli bilişim motoru dosya başlıklarını, EXIF verilerini, gömülü yükleri ve AI modellerini çalıştırıyor..."):
            report_data = None
            if backend_mode == "FastAPI REST API":
                try:
                    files = {"file": (filename, file_bytes, uploaded_file.type or "application/octet-stream")}
                    resp = requests.post(f"{api_url}/api/v1/analyze", files=files, timeout=60)
                    if resp.status_code == 200:
                        report_data = resp.json()
                    else:
                        st.error(f"FastAPI hatası: {resp.status_code} - {resp.text}")
                except Exception as e:
                    st.warning(f"FastAPI bağlantısı kurulamadı ({e}). Yerel modüle geçiliyor...")
                    report_data = run_local_analysis(file_bytes, filename)
            else:
                report_data = run_local_analysis(file_bytes, filename)

        if report_data:
            st.session_state["report_data"] = report_data
            st.session_state["pdf_path"] = report_data.get("pdf_path")
            st.success("✅ Adli Bilişim Analizi ve Rapor Üretimi Başarıyla Tamamlandı!")

# ----------------- ANALİZ SONUÇLARI GÖRÜNÜMÜ -----------------
if "report_data" in st.session_state:
    data = st.session_state["report_data"]
    magic_res = data.get("magic_bytes", {})
    hashes_res = data.get("hashes", {})
    exif_res = data.get("exif", {})
    carver_res = data.get("file_carver", {})
    cv_res = data.get("cv_analysis", {})
    threat_info = data.get("threat_assessment", {})

    score = threat_info.get("security_score", 0)
    level = threat_info.get("threat_level", "CLEAN")

    st.markdown("---")
    st.subheader("📊 Analiz & Tehdit Değerlendirme Özeti")

    # Üst Metrik Kartları
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if level == "CRITICAL":
            st.error(f"🚨 Tehdit Skoru: {score}/100\n\nKRİTİK İHLAL")
        elif level == "SUSPICIOUS":
            st.warning(f"⚠️ Tehdit Skoru: {score}/100\n\nŞÜPHELİ")
        else:
            st.success(f"🛡️ Tehdit Skoru: {score}/100\n\nTEMİZ / DOĞRULANDI")

    with col2:
        is_spoofed = magic_res.get("spoof_detected", False)
        if is_spoofed:
            st.error("🧬 Magic Bytes\n\nSAHTE UZANTI!")
        else:
            st.success("🧬 Magic Bytes\n\nUzantı Doğrulandı")

    with col3:
        has_payload = carver_res.get("payload_detected", False)
        if has_payload:
            st.error("📦 File Carving\n\nGÖMÜLÜ YÜK BULUNDU!")
        elif carver_res.get("has_appended_data"):
            st.warning("📦 File Carving\n\nEOF Sonrası Ek Veri")
        else:
            st.success("📦 File Carving\n\nTemiz / Ek Veri Yok")

    with col4:
        deepfake_p = cv_res.get("deepfake_probability", 0.0)
        if deepfake_p > 0.6:
            st.error(f"🤖 Deepfake Analizi\n\n%{deepfake_p*100:.1f} Yüksek Risk")
        else:
            st.info(f"🤖 Deepfake Analizi\n\n%{deepfake_p*100:.1f} Normal")

    st.markdown("---")

    # Sekmeli Detaylı Rapor
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🛡️ Magic Bytes & Bütünlük",
        "📸 EXIF & GPS Haritası",
        "🔍 File Carver (Binwalk)",
        "🔑 Kriptografik Hash'ler",
        "🔬 AI & Isı Haritaları",
        "📄 Adli PDF Raporu"
    ])

    # TAB 1: Magic Bytes
    with tab1:
        st.markdown("### Dosya Başlığı (Magic Bytes) ve Uzantı Doğrulaması")
        st.write(magic_res.get("details", ""))

        c_m1, c_m2 = st.columns(2)
        with c_m1:
            st.markdown(f"**Beyan Edilen Uzantı:** `{magic_res.get('declared_extension')}`")
            st.markdown(f"**Tespit Edilen Gerçek Format:** `{magic_res.get('detected_format')}`")
            st.markdown(f"**MIME Türü:** `{magic_res.get('detected_mime')}`")
        with c_m2:
            st.markdown(f"**İlk 16 Byte (Hex):**")
            st.code(magic_res.get("magic_hex_spaced", "-"), language="text")
            st.markdown(f"**Uzantı Yanıltması (Spoofing):** {'🚨 EVET' if magic_res.get('spoof_detected') else '✅ HAYIR'}")

    # TAB 2: EXIF & GPS Haritası
    with tab2:
        st.markdown("### EXIF Metadata ve Coğrafi Konum Analizi")
        if not exif_res.get("exif_found"):
            st.info("Bu dosyada EXIF üst verisi bulunamadı veya temizlenmiş.")
        else:
            ce1, ce2 = st.columns(2)
            with ce1:
                st.markdown(f"**Kamera Markası:** {exif_res.get('camera_make')}")
                st.markdown(f"**Kamera Modeli:** {exif_res.get('camera_model')}")
                st.markdown(f"**Çekim Tarihi:** {exif_res.get('date_time_original')}")
                st.markdown(f"**Kullanılan Yazılım:** {exif_res.get('software')}")
            with ce2:
                if exif_res.get("software_tampering_suspect"):
                    st.error(f"⚠️ Manipülasyon İzi: {exif_res.get('tampering_software')}")
                else:
                    st.success("✅ Bilinen düzenleme yazılımı izi yok.")

            # GPS Harita Gösterimi
            gps = exif_res.get("gps", {})
            if gps.get("has_gps") and gps.get("latitude") and gps.get("longitude"):
                st.markdown("#### 📍 Çekim Yapılan Coğrafi Konum (Harita)")
                lat = gps.get("latitude")
                lon = gps.get("longitude")
                df_gps = pd.DataFrame([{"lat": lat, "lon": lon}])
                st.map(df_gps, zoom=13)
                st.markdown(f"[Google Maps üzerinde aç]({gps.get('maps_url')})")
            else:
                st.info("GPS coğrafi konum bilgisi bulunamadı.")

            with st.expander("Tüm Ham EXIF Etiketlerini Göster"):
                st.json(exif_res.get("all_tags", {}))

    # TAB 3: File Carver
    with tab3:
        st.markdown("### Dosya Oyma (File Carver & Binwalk) Analizi")
        st.write(carver_res.get("details", ""))

        cc1, cc2 = st.columns(2)
        with cc1:
            st.markdown(f"**Toplam Boyut:** {carver_res.get('total_file_size')} bytes")
            st.markdown(f"**EOF (End of File) Offseti:** `{hex(carver_res.get('eof_offset')) if carver_res.get('eof_offset') else '-'}`")
            st.markdown(f"**EOF Sonrası Ek Veri:** {'🚨 MEVCUT' if carver_res.get('has_appended_data') else '✅ Yok'}")
            st.markdown(f"**İliştirilmiş Veri Boyutu:** {carver_res.get('appended_bytes_length', 0)} bytes")
        with cc2:
            st.markdown(f"**Veri Entropisi:** `{carver_res.get('appended_entropy', 0.0)} / 8.0`")
            st.progress(min(carver_res.get("appended_entropy", 0.0) / 8.0, 1.0))
            if carver_res.get("appended_signatures"):
                st.markdown("**Tespit Edilen Gömülü İmzalar:**")
                for s in carver_res.get("appended_signatures", []):
                    st.warning(f"• {s.get('description')} (Offset: {s.get('hex_offset')})")

    # TAB 4: Hashes & Reputation
    with tab4:
        st.markdown("### Kriptografik Özetler & Delil Bütünlüğü")
        st.text_input("MD5:", value=hashes_res.get("md5", ""), disabled=True)
        st.text_input("SHA-1:", value=hashes_res.get("sha1", ""), disabled=True)
        st.text_input("SHA-256:", value=hashes_res.get("sha256", ""), disabled=True)

        rep = hashes_res.get("reputation", {})
        if rep.get("is_known_malicious"):
            st.error(f"🚨 Tehdit İstihbaratı Eşleşmesi: {rep.get('threat_name')} ({rep.get('threat_category')})")
        else:
            st.success("✅ Kriptografik özetler bilinen tehdit veritabanlarıyla eşleşmedi (Temiz).")

        st.markdown(f"[VirusTotal Sorgula]({rep.get('virustotal_url')}) | [MalwareBazaar Sorgula]({rep.get('malwarebazaar_url')})")

    # TAB 5: AI & Isı Haritaları
    with tab5:
        st.markdown("### 🤖 Deepfake & Görüntü Manipülasyon Analizi")

        deepfake_p = cv_res.get("deepfake_probability", 0.0)
        verdict = cv_res.get("verdict", "")
        fired = cv_res.get("fired_techniques", 0)
        confidence = cv_res.get("confidence_score", 1.0)
        cv_status = cv_res.get("status", "skipped")

        # Analiz motoru etiketi
        if cv_status == "heuristic":
            st.info("🔬 **Analiz Motoru:** Heuristik ELA + FFT + DCT + Entropi + EXIF + Renk Kanalı (Torch bağımlılığı yok)")
        elif cv_status == "success":
            st.info("🧠 **Analiz Motoru:** Phase 1 CV Engine (EfficientNet / Mediapipe)")
        else:
            st.warning("⚠️ Görüntü analizi yapılamadı veya dosya görüntü formatında değil.")

        # Üst metrik satırı
        c_cv1, c_cv2, c_cv3, c_cv4 = st.columns(4)
        with c_cv1:
            pct = deepfake_p * 100
            if deepfake_p >= 0.70:
                st.error(f"🚨 Deepfake Olasılığı\n\n**%{pct:.1f}**")
            elif deepfake_p >= 0.45:
                st.warning(f"⚠️ Deepfake Olasılığı\n\n**%{pct:.1f}**")
            elif deepfake_p >= 0.25:
                st.warning(f"🔶 Deepfake Olasılığı\n\n**%{pct:.1f}** (Düşük Şüphe)")
            else:
                st.success(f"✅ Deepfake Olasılığı\n\n**%{pct:.1f}** Normal")

        with c_cv2:
            verdict_label = {
                "DEEPFAKE": "🚨 DEEPFAKE",
                "ŞÜPHELİ_DEEPFAKE": "⚠️ ŞÜPHELİ",
                "DÜŞÜK_ŞÜPHELİ": "🔶 DÜŞÜK ŞÜPHELİ",
                "NORMAL": "✅ NORMAL",
            }.get(verdict, f"— {verdict}")
            st.metric("Karar", verdict_label)

        with c_cv3:
            st.metric("Ateşlenen Teknik", f"{fired} / 6")

        with c_cv4:
            st.metric("Görsel Entropi", f"{cv_res.get('entropy_score', 0.0):.4f}")

        # Deepfake göstergesi ilerleme çubuğu
        st.markdown("#### 📊 Deepfake Olasılık Ölçeği")
        st.progress(min(deepfake_p, 1.0))
        col_l, col_r = st.columns([1, 1])
        with col_l:
            st.caption("0% → Kesinlikle Gerçek")
        with col_r:
            st.markdown("<div style='text-align:right'>100% → Kesinlikle Deepfake</div>", unsafe_allow_html=True)

        # Uyarı göstergeleri
        indicators = cv_res.get("indicators", [])
        if indicators and indicators[0] != "Hiçbir teknik belirgin anomali tespit etmedi.":
            st.markdown("#### 🚩 Tespit Edilen Anomali Göstergeleri")
            for ind in indicators:
                st.error(f"• {ind}")
        else:
            st.success("✅ Hiçbir teknik belirgin anomali tespit etmedi.")

        # Teknik detay tablosu
        technique_results = cv_res.get("technique_results", {})
        if technique_results:
            st.markdown("#### 🔬 Teknik Analiz Kırılımı")
            tech_labels = {
                "ela": "ELA (Hata Düzeyi)",
                "fft": "FFT (Frekans)",
                "dct": "DCT (Blok Tutarsızlık)",
                "entropy_inconsistency": "Entropi Tutarsızlığı",
                "exif_anomaly": "EXIF Anomali",
                "color_channels": "Renk Kanalı"
            }
            rows = []
            for key, label in tech_labels.items():
                tech = technique_results.get(key, {})
                rows.append({
                    "Teknik": label,
                    "Skor": f"{tech.get('score', 0.0):.3f}",
                    "Uyarı": "🚨 EVET" if tech.get("fired") else "✅ Hayır",
                    "Açıklama": tech.get("detail", "-")
                })
            st.dataframe(rows, use_container_width=True)

        # Isı haritası görselleri (Phase 1 varsa)
        ela_img = cv_res.get("ela_image_path")
        fft_img = cv_res.get("fft_spectrum_path")
        bit_img = cv_res.get("bit_planes_path")

        if any(p and os.path.exists(p) for p in [ela_img, fft_img, bit_img]):
            st.markdown("#### 🗺️ Görsel Isı Haritaları (Phase 1 CV)")
            cols = st.columns(3)
            if ela_img and os.path.exists(ela_img):
                with cols[0]:
                    st.image(ela_img, caption="Hata Düzeyi Analizi (ELA)", use_column_width=True)
            if fft_img and os.path.exists(fft_img):
                with cols[1]:
                    st.image(fft_img, caption="FFT Frekans Spektrumu", use_column_width=True)
            if bit_img and os.path.exists(bit_img):
                with cols[2]:
                    st.image(bit_img, caption="Bit-Plane Dağılımı", use_column_width=True)

    # TAB 6: PDF Raporu
    with tab6:
        st.markdown("### 📄 Resmi Adli Bilişim İnceleme Raporu (PDF)")
        st.write("ReportLab motoru kullanılarak T.C. resmi adli standartlarına uygun PDF raporu üretilmiştir.")

        pdf_path = st.session_state.get("pdf_path")
        if pdf_path and os.path.exists(pdf_path):
            with open(pdf_path, "rb") as pdf_file:
                pdf_bytes = pdf_file.read()

            st.download_button(
                label="📥 Resmi Adli Bilişim PDF Raporunu İndir",
                data=pdf_bytes,
                file_name=f"Forensic_Report_{data.get('analysis_id')}.pdf",
                mime="application/pdf",
                type="primary"
            )
            st.success(f"PDF Raporu Hazır ({len(pdf_bytes):,} Bytes). Yukarıdaki butondan indirebilirsiniz.")
        else:
            st.warning("PDF raporu henüz oluşturulmadı veya dosya bulunamadı.")
