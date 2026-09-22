"""
Forensic Vision - Backend ve Adli Bilişim Modülleri Test Betiği
Tüm modülleri (Magic bytes, EXIF, File Carving, Hashing, PDF Generator ve FastAPI REST API)
sentetik adli deliller üreterek uçtan uca doğrular.
"""

import os
import sys
import shutil
import tempfile
import struct

# Windows konsolunda UTF-8 emoji ve Türkçe karakter desteği
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from PIL import Image, ImageDraw
import piexif

# Modülleri içe aktarabilmek için yolu ekle
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from forensics.magic_bytes import verify_file_integrity
from forensics.exif_parser import extract_exif
from forensics.file_carver import detect_appended_payload
from forensics.hash_lookup import calculate_hashes
from reports.pdf_generator import generate_forensic_pdf
from main import app


def create_test_evidence(test_dir: str):
    """
    Testler için sentetik adli delil dosyaları üretir:
    1. Temiz, EXIF ve GPS içeren gerçek JPEG.
    2. Sahte uzantılı dosya (İçeriği EXE/ZIP olan sahte .jpg).
    3. EOF arkasına gömülü ZIP yükü iliştirilmiş görsel (File Carving / Polyglot testi).
    """
    os.makedirs(test_dir, exist_ok=True)

    # 1. Temiz Görsel + EXIF ve GPS
    clean_jpg = os.path.join(test_dir, "evidence_clean.jpg")
    img = Image.new("RGB", (200, 200), color=(73, 109, 137))
    d = ImageDraw.Draw(img)
    d.text((10, 10), "Forensic Vision Test", fill=(255, 255, 0))

    # EXIF ve GPS verisi inşa et
    zeroth_ifd = {
        piexif.ImageIFD.Make: u"Nikon",
        piexif.ImageIFD.Model: u"D850",
        piexif.ImageIFD.Software: u"Adobe Photoshop 2024",  # Manipülasyon testi için
        piexif.ImageIFD.DateTime: u"2026:09:22 17:00:00"
    }
    exif_ifd = {
        piexif.ExifIFD.DateTimeOriginal: u"2026:09:22 17:00:00"
    }
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((41, 1), (0, 1), (49, 1)),   # 41.0136 N
        piexif.GPSIFD.GPSLongitudeRef: "E",
        piexif.GPSIFD.GPSLongitude: ((28, 1), (58, 1), (42, 1)), # 28.9783 E
        piexif.GPSIFD.GPSAltitude: (50, 1)
    }
    exif_dict = {"0th": zeroth_ifd, "Exif": exif_ifd, "GPS": gps_ifd}
    exif_bytes = piexif.dump(exif_dict)
    img.save(clean_jpg, "jpeg", exif=exif_bytes)

    # 2. Sahte Uzantılı Dosya (Spoofed File)
    # Gerçekte Windows PE Executable (MZ) veya ZIP dosyası, ancak uzantısı .jpg
    spoofed_jpg = os.path.join(test_dir, "evidence_spoofed.jpg")
    pe_header = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 100)
    with open(spoofed_jpg, "wb") as f:
        f.write(pe_header)

    # 3. Dosya Sonuna Gömülü ZIP Yükü Olan Görsel (Appended Payload / Carving)
    carved_jpg = os.path.join(test_dir, "evidence_carved_payload.jpg")
    with open(clean_jpg, "rb") as f:
        clean_bytes = f.read()

    # Sahte ZIP yerel başlığı (PK\x03\x04) ve gizli yük
    zip_dummy_payload = (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x0a\x00\x00\x00secret.txtGIZLI_VERI_VE_ZARARLI_YUK_12345678"
        b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x38\x00\x00\x00\x2a\x00\x00\x00\x00\x00"
    )

    with open(carved_jpg, "wb") as f:
        f.write(clean_bytes + zip_dummy_payload)

    return clean_jpg, spoofed_jpg, carved_jpg


def run_tests():
    print("\n" + "=" * 65)
    print("🛡️  FORENSIC VISION - SİBER ADLİ BİLİŞİM TEST SÜRECİ BAŞLATILIYOR")
    print("=" * 65)

    test_temp_dir = tempfile.mkdtemp(prefix="forensic_test_")
    clean_jpg, spoofed_jpg, carved_jpg = create_test_evidence(test_temp_dir)

    try:
        # TEST 1: Magic Bytes Doğrulama
        print("\n[TEST 1] Magic Bytes & Uzantı Doğrulama (magic_bytes.py)...")
        res_clean_mb = verify_file_integrity(clean_jpg)
        assert res_clean_mb["status"] == "success", "Clean dosya okunamadı!"
        assert not res_clean_mb["spoof_detected"], "HATA: Temiz dosyada sahte uzantı tespit edildi!"
        assert res_clean_mb["detected_format"].startswith("JPEG"), "Format JPEG olarak algılanamadı!"
        print(f"  ✅ Temiz JPEG Doğrulandı: {res_clean_mb['detected_format']} | Magic: {res_clean_mb['magic_hex_16']}")

        res_spoof_mb = verify_file_integrity(spoofed_jpg)
        assert res_spoof_mb["spoof_detected"], "HATA: Sahte uzantı (spoofed) tespit edilemedi!"
        assert res_spoof_mb["threat_level"] in ["CRITICAL", "HIGH"], "Tehdit seviyesi yüksek değil!"
        print(f"  ✅ Sahte Uzantı Başarıyla Yakalandı! Tespit Edilen: {res_spoof_mb['detected_format']}")

        # TEST 2: EXIF & GPS Parser
        print("\n[TEST 2] EXIF & GPS Ayrıştırma (exif_parser.py)...")
        res_exif = extract_exif(clean_jpg)
        assert res_exif["status"] == "success", "EXIF çıkarma başarısız!"
        assert res_exif["exif_found"], "EXIF verisi bulunamadı!"
        assert res_exif["camera_make"] == "Nikon", f"Kamera markası yanlış: {res_exif['camera_make']}"
        assert res_exif["camera_model"] == "D850", f"Kamera modeli yanlış: {res_exif['camera_model']}"
        assert res_exif["software_tampering_suspect"], "Photoshop yazılım izi tespit edilemedi!"
        assert res_exif["gps"]["has_gps"], "GPS konumu tespit edilemedi!"
        print(f"  ✅ Kamera: {res_exif['camera_make']} {res_exif['camera_model']}")
        print(f"  ✅ Manipülasyon İzi: {res_exif['tampering_software']}")
        print(f"  ✅ GPS Konumu: {res_exif['gps']['coordinates_str']} (Lat: {res_exif['gps']['latitude']}, Lon: {res_exif['gps']['longitude']})")

        # TEST 3: File Carver (Binwalk EOF Mantığı)
        print("\n[TEST 3] File Carving & Appended Payload Tespiti (file_carver.py)...")
        res_clean_carv = detect_appended_payload(clean_jpg)
        assert not res_clean_carv["payload_detected"], "Temiz dosyada yanlış alarm!"
        print("  ✅ Temiz dosya EOF sınırları doğrulandı (Ek veri yok).")

        res_carved = detect_appended_payload(carved_jpg)
        assert res_carved["has_appended_data"], "EOF arkasındaki ek veri tespit edilemedi!"
        assert res_carved["payload_detected"], "Gömülü ZIP yükü alarm vermedi!"
        assert res_carved["appended_bytes_length"] > 0, "Ek veri boyutu sıfır!"
        assert len(res_carved["appended_signatures"]) > 0, "ZIP imzası bulunamadı!"
        print(f"  ✅ Gömülü Yük Tespit Edildi! EOF: {hex(res_carved['eof_offset'])} | Ek Veri: {res_carved['appended_bytes_length']} Bytes")
        print(f"  ✅ İmzalar: {[s['description'] for s in res_carved['appended_signatures']]}")

        # TEST 4: Kriptografik Özetler (Hashing & Reputation)
        print("\n[TEST 4] Kriptografik Hashing & İtibar Kontrolü (hash_lookup.py)...")
        res_hashes = calculate_hashes(clean_jpg)
        assert res_hashes["status"] == "success", "Hash hesaplama hatası!"
        assert len(res_hashes["md5"]) == 32, "MD5 formatı geçersiz!"
        assert len(res_hashes["sha1"]) == 40, "SHA-1 formatı geçersiz!"
        assert len(res_hashes["sha256"]) == 64, "SHA-256 formatı geçersiz!"
        print(f"  ✅ MD5   : {res_hashes['md5']}")
        print(f"  ✅ SHA-1 : {res_hashes['sha1']}")
        print(f"  ✅ SHA256: {res_hashes['sha256']}")
        print(f"  ✅ İtibar: {res_hashes['reputation']['details']}")

        # TEST 5: ReportLab PDF Rapor Oluşturucu
        print("\n[TEST 5] ReportLab Resmi Adli Bilişim PDF Raporlama (pdf_generator.py)...")
        test_pdf_out = os.path.join(test_temp_dir, "test_forensic_report.pdf")
        report_payload = {
            "analysis_id": "TEST-8842",
            "file_name": os.path.basename(carved_jpg),
            "magic_bytes": res_clean_mb,
            "hashes": res_hashes,
            "exif": res_exif,
            "file_carver": res_carved,
            "cv_analysis": {
                "deepfake_probability": 0.15,
                "entropy_score": 7.42,
                "is_stego_suspect": False
            }
        }
        pdf_path = generate_forensic_pdf(report_payload, test_pdf_out)
        assert os.path.exists(pdf_path), "PDF dosyası oluşturulamadı!"
        assert os.path.getsize(pdf_path) > 1000, "PDF dosyası boş veya çok küçük!"
        print(f"  ✅ Adli Bilişim PDF Raporu Oluşturuldu ({os.path.getsize(pdf_path)} Bytes): {pdf_path}")

        # TEST 6: FastAPI REST API Uç Noktaları
        print("\n[TEST 6] FastAPI REST API Sunucu Uç Noktaları (main.py)...")
        from fastapi.testclient import TestClient
        client = TestClient(app)

        # Health endpoint
        resp_health = client.get("/api/v1/health")
        assert resp_health.status_code == 200, f"Health endpoint hatası: {resp_health.status_code}"
        assert resp_health.json()["status"] == "healthy"
        print("  ✅ GET /api/v1/health -> 200 OK")

        # Analyze endpoint (Dosya yükleme & analiz)
        with open(carved_jpg, "rb") as f:
            upload_files = {"file": ("evidence_carved_payload.jpg", f, "image/jpeg")}
            resp_analyze = client.post("/api/v1/analyze", files=upload_files)
        assert resp_analyze.status_code == 200, f"Analyze endpoint hatası: {resp_analyze.status_code} - {resp_analyze.text}"
        data_analyze = resp_analyze.json()
        assert "analysis_id" in data_analyze, "Analiz yanıtında analysis_id eksik!"
        analysis_id = data_analyze["analysis_id"]
        assert data_analyze["threat_assessment"]["threat_level"] in ["CRITICAL", "HIGH", "SUSPICIOUS"]
        print(f"  ✅ POST /api/v1/analyze -> 200 OK (Analysis ID: {analysis_id})")

        # Report download endpoint
        resp_report = client.get(f"/api/v1/report/{analysis_id}")
        assert resp_report.status_code == 200, f"Report download hatası: {resp_report.status_code}"
        assert resp_report.headers["content-type"] == "application/pdf"
        assert len(resp_report.content) > 1000
        print(f"  ✅ GET /api/v1/report/{analysis_id} -> 200 OK ({len(resp_report.content)} Bytes PDF İndirildi)")

        print("\n" + "=" * 65)
        print("🎉 TÜM BACKEND & ADLİ BİLİŞİM TESTLERİ EKSİKSİZ VE BAŞARIYLA GEÇTİ!")
        print("=" * 65 + "\n")

    finally:
        shutil.rmtree(test_temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_tests()
