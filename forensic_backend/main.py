"""
Forensic Vision - FastAPI Adli Bilişim & Siber Güvenlik REST API Sunucusu
Dosya yükleme, adli bilişim analizi (Magic bytes, EXIF, Carving, Hashes, CV Isı haritaları)
ve resmi ReportLab PDF raporu oluşturma uç noktalarını sunar.
"""

import os
import sys
import uuid
import time
import shutil
from typing import Dict, Any, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Üst dizindeki cv_engine modülünü yüklemek için sys.path güncelle
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Alt adli bilişim modüllerini içe aktar
from forensics.magic_bytes import verify_file_integrity
from forensics.exif_parser import extract_exif
from forensics.file_carver import detect_appended_payload
from forensics.hash_lookup import calculate_hashes
from reports.pdf_generator import generate_forensic_pdf

# 1. Aşama Computer Vision motoru kontrolü
CV_AVAILABLE = False
cv_engine = None
try:
    from cv_engine import ForensicCVEngine
    cv_engine = ForensicCVEngine(default_output_dir=os.path.join(CURRENT_DIR, "outputs"))
    CV_AVAILABLE = True
except Exception:
    CV_AVAILABLE = False

# Dizinleri hazırla
UPLOADS_DIR = os.path.join(CURRENT_DIR, "uploads")
OUTPUTS_DIR = os.path.join(CURRENT_DIR, "outputs")
REPORTS_DIR = os.path.join(CURRENT_DIR, "reports_generated")

for d in [UPLOADS_DIR, OUTPUTS_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)

# Bellek içi analiz önbelleği (In-memory analysis cache)
ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}

app = FastAPI(
    title="Forensic Vision API",
    description="Siber Güvenlik, Dosya Adli Bilişimi, Görüntü Bütünlüğü & PDF Raporlama Servisi",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware (Streamlit ve diğer istemciler için)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Çıktı görsellerini statik olarak yayınla
app.mount("/static/outputs", StaticFiles(directory=OUTPUTS_DIR), name="outputs")


def compute_threat_assessment(magic_res: dict, carver_res: dict, hashes_res: dict, exif_res: dict, cv_res: dict) -> Dict[str, Any]:
    """
    Tüm modüllerden gelen bulguları birleştirerek ağırlıklı Tehdit Skoru (0-100) ve Risk Seviyesi belirler.
    """
    score = 0
    violations = []

    # 1. Magic Bytes / Spoofing
    if magic_res.get("spoof_detected"):
        score += 40
        violations.append(f"Uzantı Yanıltması (Spoofing): {magic_res.get('details')}")

    # 2. File Carving / Appended Payload
    if carver_res.get("payload_detected"):
        score += 45
        violations.append(f"EOF Sonrası Gizli Veri / Payload: {carver_res.get('details')}")
    elif carver_res.get("has_appended_data"):
        score += 25
        violations.append("Dosya sonu (EOF) sonrasında ek veri (Overlay) tespit edildi.")

    # 3. Zararlı Hash İtibarı
    if hashes_res.get("reputation", {}).get("is_known_malicious"):
        score += 50
        violations.append(f"Zararlı Yazılım Eşleşmesi: {hashes_res['reputation'].get('threat_name')}")

    # 4. EXIF Manipülasyon İzi
    if exif_res.get("software_tampering_suspect"):
        score += 20
        violations.append(f"Manipülasyon Yazılımı İzi: {exif_res.get('tampering_software')}")

    # 5. Computer Vision & Deepfake
    deepfake_prob = cv_res.get("deepfake_probability", 0.0)
    if deepfake_prob > 0.6:
        score += int(deepfake_prob * 35)
        violations.append(f"Yüksek Deepfake Olasılığı: %{deepfake_prob * 100:.1f}")

    if cv_res.get("is_stego_suspect"):
        score += 25
        violations.append("Görsel piksel seviyesinde Steganografi şüphesi tespit edildi.")

    score = min(max(score, 0), 100)

    if score >= 70:
        level = "CRITICAL"
        status_label = "YÜKSEK TEHDİT / ZARARLI İHLAL"
    elif score >= 35:
        level = "SUSPICIOUS"
        status_label = "ŞÜPHELİ / MANİPÜLE EDİLMİŞ OLABİLİR"
    else:
        level = "CLEAN"
        status_label = "TEMİZ / DOĞRULANDI"

    return {
        "security_score": score,
        "threat_level": level,
        "threat_status_label": status_label,
        "violations": violations
    }


@app.get("/")
def root():
    return {
        "name": "Forensic Vision Digital Evidence & Security API",
        "version": "2.0.0",
        "documentation": "/docs",
        "cv_engine_available": CV_AVAILABLE,
        "status": "operational"
    }


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "modules": {
            "magic_bytes": True,
            "exif_parser": True,
            "file_carver": True,
            "hash_lookup": True,
            "pdf_generator": True,
            "cv_engine": CV_AVAILABLE
        },
        "storage": {
            "uploads_dir": UPLOADS_DIR,
            "reports_dir": REPORTS_DIR,
            "outputs_dir": OUTPUTS_DIR
        }
    }


@app.post("/api/v1/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Dosya yükleme & tam adli bilişim analizi başlatma uç noktası.
    Magic Bytes, EXIF, File Carving, Hashes, CV Isı haritaları ve PDF raporunu üretir.
    """
    analysis_id = uuid.uuid4().hex[:12]
    original_filename = file.filename or "unknown_evidence.bin"
    file_ext = os.path.splitext(original_filename)[1]

    # Geçici yükleme yolunu belirle
    saved_file_path = os.path.join(UPLOADS_DIR, f"{analysis_id}_{original_filename}")

    try:
        with open(saved_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dosya kaydedilemedi: {str(e)}")

    # 1. Bütünlük & Magic Bytes Analizi
    magic_result = verify_file_integrity(saved_file_path)

    # 2. Kriptografik Özetler (Hashes) & İtibar
    hashes_result = calculate_hashes(saved_file_path)

    # 3. EXIF Metadata & GPS Analizi
    exif_result = extract_exif(saved_file_path)

    # 4. File Carving & Appended Payload Analizi
    carver_result = detect_appended_payload(saved_file_path)

    # 5. Computer Vision & Isı Haritaları (Phase 1 entegrasyonu)
    cv_result = {
        "status": "skipped",
        "deepfake_probability": 0.0,
        "entropy_score": 0.0,
        "is_stego_suspect": False,
        "ela_image_path": None,
        "fft_spectrum_path": None,
        "bit_planes_path": None
    }

    if CV_AVAILABLE and file_ext.lower() in [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"]:
        try:
            cv_res_raw = cv_engine.analyze_media(saved_file_path, output_dir=OUTPUTS_DIR)
            if cv_res_raw.get("status") == "success":
                cv_result = cv_res_raw
        except Exception as e:
            cv_result["message"] = f"CV motoru analizi sırasında hata: {str(e)}"

    # 6. Genel Tehdit & Risk Puanlaması
    threat_assessment = compute_threat_assessment(
        magic_result, carver_result, hashes_result, exif_result, cv_result
    )

    # 7. Adli Bilişim PDF Raporu Oluştur
    pdf_filename = f"forensic_report_{analysis_id}.pdf"
    pdf_output_path = os.path.join(REPORTS_DIR, pdf_filename)

    full_report_data = {
        "analysis_id": analysis_id,
        "timestamp": int(time.time()),
        "file_name": original_filename,
        "magic_bytes": magic_result,
        "hashes": hashes_result,
        "exif": exif_result,
        "file_carver": carver_result,
        "cv_analysis": cv_result,
        "threat_assessment": threat_assessment
    }

    try:
        generate_forensic_pdf(full_report_data, pdf_output_path)
    except Exception as e:
        pdf_output_path = None
        full_report_data["pdf_error"] = str(e)

    full_report_data["pdf_path"] = pdf_output_path
    full_report_data["report_download_url"] = f"/api/v1/report/{analysis_id}"

    # Önbelleğe kaydet
    ANALYSIS_CACHE[analysis_id] = full_report_data

    return JSONResponse(status_code=200, content=full_report_data)


@app.get("/api/v1/report/{analysis_id}")
def download_pdf_report(analysis_id: str):
    """
    Belirtilen analiz ID'sine ait adli bilişim PDF raporunu indirir.
    """
    # Önce önbelleğe bak
    cached = ANALYSIS_CACHE.get(analysis_id)
    pdf_path = cached.get("pdf_path") if cached else None

    # Disk üzerinde doğrudan ara
    if not pdf_path or not os.path.exists(pdf_path):
        fallback_path = os.path.join(REPORTS_DIR, f"forensic_report_{analysis_id}.pdf")
        if os.path.exists(fallback_path):
            pdf_path = fallback_path

    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Adli bilişim PDF raporu bulunamadı.")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"Adli_Bilisim_Raporu_{analysis_id}.pdf"
    )


@app.get("/api/v1/analyses")
def list_analyses(limit: int = Query(20, ge=1, le=100)):
    """
    Tamamlanan son adli bilişim incelemelerini listeler.
    """
    items = []
    for aid, data in list(ANALYSIS_CACHE.items())[-limit:]:
        items.append({
            "analysis_id": aid,
            "filename": data.get("file_name"),
            "threat_level": data.get("threat_assessment", {}).get("threat_level"),
            "security_score": data.get("threat_assessment", {}).get("security_score"),
            "timestamp": data.get("timestamp"),
            "report_download_url": data.get("report_download_url")
        })
    return {"total": len(ANALYSIS_CACHE), "recent": items}


if __name__ == "__main__":
    import uvicorn
    print("Forensic Vision API Başlatılıyor: http://127.0.0.1:8000 (Docs: /docs)")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
