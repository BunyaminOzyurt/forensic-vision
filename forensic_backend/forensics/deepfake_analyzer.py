"""
Forensic Vision - Heuristic Deepfake Analyzer
Torch / OpenCV / MediaPipe gerektirmeden PIL + NumPy + SciPy ile
ELA, FFT, DCT Artifact, Piksel Entropi tutarsızlığı ve EXIF Anomali
tekniklerini birleştirerek deepfake olasılığını hesaplar.
"""

import os
import io
import math
import struct
import hashlib
import tempfile
from typing import Dict, Any, List, Tuple

try:
    from PIL import Image, ImageFilter, ImageChops
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from scipy.fft import fft2, fftshift
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Yardımcı: Dosya uzantısı görüntü mü?
# ---------------------------------------------------------------------------
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"}


def _is_image(file_path: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    return ext in IMAGE_EXTENSIONS


# ---------------------------------------------------------------------------
# TEKNİK 1 — ELA (Error Level Analysis)
# Deepfake bölgeleri farklı sıkıştırma kalitesiyle montajlanmıştır;
# ELA bu bölgeleri yüksek hata düzeyiyle ortaya çıkarır.
# ---------------------------------------------------------------------------
def _ela_analysis(img: "Image.Image") -> Dict[str, Any]:
    """
    ELA uygular. Yüksek ortalama ELA değeri = sıkıştırma tutarsızlığı.
    Deepfake görüntülerde sentetik yüz bölgesi farklı ELA bırakır.
    """
    result = {"score": 0.0, "fired": False, "detail": "ELA analizi yapılamadı"}

    if not PIL_AVAILABLE or not NUMPY_AVAILABLE:
        return result

    try:
        # Görüntüyü 92 kalitede JPEG olarak yeniden sıkıştır
        temp_buf = io.BytesIO()
        img_rgb = img.convert("RGB")
        img_rgb.save(temp_buf, format="JPEG", quality=92)
        temp_buf.seek(0)
        recompressed = Image.open(temp_buf).convert("RGB")

        # Fark görüntüsü
        diff = ImageChops.difference(img_rgb, recompressed)
        diff_arr = np.array(diff, dtype=np.float32)

        mean_ela = float(np.mean(diff_arr))
        std_ela = float(np.std(diff_arr))

        # Deepfake eşiği: ortalama ELA > 8 VE std > 12 ise şüpheli
        # Normal gerçek fotoğraflar genelde 3-7 aralığında kalır
        score = min(mean_ela / 30.0, 1.0)  # 30 üzerinde maksimum
        fired = mean_ela > 7.0 or std_ela > 14.0

        result = {
            "score": round(score, 4),
            "mean_ela": round(mean_ela, 3),
            "std_ela": round(std_ela, 3),
            "fired": fired,
            "detail": f"Ortalama ELA: {mean_ela:.2f}, Standart Sapma: {std_ela:.2f}"
        }
    except Exception as e:
        result["detail"] = f"ELA hatası: {str(e)}"

    return result


# ---------------------------------------------------------------------------
# TEKNİK 2 — FFT Frekans Analizi
# GAN-üretimi görüntülerde yüksek frekanslarda karakteristik örüntüler kalır.
# Merkeze yakın frekans enerjisi ile dış bölge enerjisi oranı karşılaştırılır.
# ---------------------------------------------------------------------------
def _fft_analysis(img: "Image.Image") -> Dict[str, Any]:
    """
    FFT frekans analizi. Yapay görüntülerde frekans dağılımı doğal görüntüden
    belirgin şekilde farklılık gösterir (çok düzgün veya çok gürültülü).
    """
    result = {"score": 0.0, "fired": False, "detail": "FFT analizi yapılamadı"}

    if not NUMPY_AVAILABLE:
        return result

    try:
        gray = img.convert("L")
        arr = np.array(gray, dtype=np.float32)

        if SCIPY_AVAILABLE:
            fft = fftshift(fft2(arr))
        else:
            fft = np.fft.fftshift(np.fft.fft2(arr))

        magnitude = np.abs(fft)
        h, w = magnitude.shape
        cy, cx = h // 2, w // 2
        radius = min(h, w) // 8  # Merkez bölge

        # Merkez (düşük frekans) ve çevre (yüksek frekans) enerjisi
        y_idx, x_idx = np.ogrid[:h, :w]
        center_mask = (y_idx - cy) ** 2 + (x_idx - cx) ** 2 <= radius ** 2
        low_energy = float(np.mean(magnitude[center_mask]))
        high_energy = float(np.mean(magnitude[~center_mask]))

        ratio = low_energy / (high_energy + 1e-9)

        # Doğal fotoğraflar: ratio genellikle 15-80 arası
        # GAN görüntüleri: ratio ya çok yüksek (>120) ya çok düşük (<10) olabilir
        if ratio > 120 or ratio < 8:
            score = 0.75
            fired = True
            detail = f"Anormal FFT enerji dağılımı (ratio={ratio:.1f}). Sentetik kaynak şüphesi."
        elif ratio > 100 or ratio < 12:
            score = 0.45
            fired = True
            detail = f"Şüpheli FFT enerji oranı: {ratio:.1f}"
        else:
            score = max(0.0, (1.0 - abs(ratio - 45) / 80))
            fired = False
            detail = f"FFT enerji oranı normal aralıkta: {ratio:.1f}"

        result = {
            "score": round(min(score, 1.0), 4),
            "low_freq_energy": round(low_energy, 2),
            "high_freq_energy": round(high_energy, 2),
            "ratio": round(ratio, 2),
            "fired": fired,
            "detail": detail
        }
    except Exception as e:
        result["detail"] = f"FFT hatası: {str(e)}"

    return result


# ---------------------------------------------------------------------------
# TEKNİK 3 — DCT Artifact / Blok Tutarsızlığı Analizi
# Gerçek JPEG görüntülerde 8x8 piksel bloklarında tutarlı sıkıştırma izi olur.
# Deepfake montaj bölgeleri farklı DCT bloklarına sahiptir.
# ---------------------------------------------------------------------------
def _dct_block_analysis(img: "Image.Image") -> Dict[str, Any]:
    """
    8x8 piksel bloklarındaki yerel varyans tutarsızlığını ölçer.
    Deepfake bölgeler; çevresiyle orantısız varyans değeri verir.
    """
    result = {"score": 0.0, "fired": False, "detail": "DCT analizi yapılamadı"}

    if not NUMPY_AVAILABLE:
        return result

    try:
        gray = img.convert("L").resize((256, 256))
        arr = np.array(gray, dtype=np.float32)

        block_size = 8
        variances = []
        h, w = arr.shape

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = arr[y:y + block_size, x:x + block_size]
                variances.append(float(np.var(block)))

        if not variances:
            return result

        var_array = np.array(variances)
        mean_var = float(np.mean(var_array))
        std_var = float(np.std(var_array))
        cv = std_var / (mean_var + 1e-9)  # Değişim katsayısı

        # Yüksek CV = bloklar arası çok fazla heterojenlik = manipülasyon izi
        score = min(cv / 3.0, 1.0)
        fired = cv > 1.5

        result = {
            "score": round(score, 4),
            "block_variance_mean": round(mean_var, 2),
            "block_variance_std": round(std_var, 2),
            "coefficient_of_variation": round(cv, 4),
            "fired": fired,
            "detail": f"Blok varyans katsayısı: {cv:.3f} {'(ŞÜPHELİ: Heterojen blok dağılımı)' if fired else '(Normal)'}"
        }
    except Exception as e:
        result["detail"] = f"DCT analizi hatası: {str(e)}"

    return result


# ---------------------------------------------------------------------------
# TEKNİK 4 — Yüz Bölgesi Piksel Entropi Tutarsızlığı
# Deepfake'lerde yüz bölgesi çevresiyle farklı entropi (bilgi yoğunluğu) gösterir.
# Görüntüyü 9 bölgeye bölerek merkez (yüz) ile kenar entropisini karşılaştırır.
# ---------------------------------------------------------------------------
def _entropy_inconsistency_analysis(img: "Image.Image") -> Dict[str, Any]:
    """
    Görüntüyü 3x3 ızgaraya böler. Merkez bölgenin (yüz alanı) entropisini
    köşe bölgelerle karşılaştırır. Anormal fark deepfake işareti.
    """
    result = {"score": 0.0, "fired": False, "detail": "Entropi analizi yapılamadı"}

    if not NUMPY_AVAILABLE:
        return result

    try:
        gray = img.convert("L").resize((192, 192))
        arr = np.array(gray, dtype=np.float32)
        h, w = arr.shape
        bh, bw = h // 3, w // 3

        def block_entropy(region):
            flat = region.flatten().astype(int)
            hist, _ = np.histogram(flat, bins=256, range=(0, 255))
            hist = hist[hist > 0]
            p = hist / hist.sum()
            return -float(np.sum(p * np.log2(p + 1e-12)))

        # 3x3 ızgara bloklarının entropileri
        entropies = []
        for gy in range(3):
            row = []
            for gx in range(3):
                region = arr[gy*bh:(gy+1)*bh, gx*bw:(gx+1)*bw]
                row.append(block_entropy(region))
            entropies.append(row)

        center_entropy = entropies[1][1]
        corner_entropies = [entropies[0][0], entropies[0][2], entropies[2][0], entropies[2][2]]
        mean_corner = float(np.mean(corner_entropies))

        diff = abs(center_entropy - mean_corner)

        # Fark > 1.5 bit çok yüksek; gerçek fotoğraflarda genellikle < 0.8
        score = min(diff / 3.0, 1.0)
        fired = diff > 1.2

        result = {
            "score": round(score, 4),
            "center_entropy": round(center_entropy, 4),
            "corner_entropy_mean": round(mean_corner, 4),
            "entropy_diff": round(diff, 4),
            "fired": fired,
            "detail": f"Merkez-Kenar Entropi Farkı: {diff:.3f} bit {'(ŞÜPHELİ)' if fired else '(Normal)'}"
        }
    except Exception as e:
        result["detail"] = f"Entropi analizi hatası: {str(e)}"

    return result


# ---------------------------------------------------------------------------
# TEKNİK 5 — EXIF / Metadata Anomali Analizi
# Deepfake ve AI-generated görüntüler genellikle EXIF içermez veya
# kamera bilgisi yerine yazılım bilgisi içerir.
# ---------------------------------------------------------------------------
def _exif_anomaly_analysis(file_path: str) -> Dict[str, Any]:
    """
    EXIF metadata varlığı ve içeriğini deepfake göstergesi olarak değerlendirir.
    """
    result = {"score": 0.0, "fired": False, "detail": "EXIF analizi yapılamadı"}

    if not PIL_AVAILABLE:
        return result

    try:
        img = Image.open(file_path)
        exif_data = img._getexif() if hasattr(img, "_getexif") else None

        if exif_data is None:
            # JPEG'de EXIF yoksa şüpheli (gerçek fotoğraflar genellikle EXIF içerir)
            ext = os.path.splitext(file_path)[1].lower()
            if ext in {".jpg", ".jpeg"}:
                result = {
                    "score": 0.55,
                    "fired": True,
                    "has_exif": False,
                    "detail": "JPEG dosyasında EXIF verisi YOK — AI-generated veya strip edilmiş olabilir."
                }
            else:
                result = {
                    "score": 0.1,
                    "fired": False,
                    "has_exif": False,
                    "detail": "EXIF verisi yok (PNG/WebP için normal)."
                }
            return result

        # EXIF varsa kamera vs yazılım kontrolü
        MAKE_TAG = 271
        MODEL_TAG = 272
        SOFTWARE_TAG = 305
        DATETIME_TAG = 306

        has_make = MAKE_TAG in exif_data and exif_data[MAKE_TAG]
        has_model = MODEL_TAG in exif_data and exif_data[MODEL_TAG]
        has_software = SOFTWARE_TAG in exif_data
        software_val = str(exif_data.get(SOFTWARE_TAG, "")).lower()

        # AI araç imzaları
        ai_tools = ["stable diffusion", "midjourney", "dall-e", "diffusion",
                    "automatic1111", "comfyui", "invokeai", "novelai", "dreamstudio",
                    "adobe firefly", "firefly", "generative fill"]
        ai_detected = any(tool in software_val for tool in ai_tools)

        if ai_detected:
            score = 0.95
            fired = True
            detail = f"AI görüntü aracı imzası tespit edildi: '{exif_data.get(SOFTWARE_TAG)}'"
        elif not has_make and not has_model:
            score = 0.4
            fired = True
            detail = "Kamera markası/modeli eksik, yazılımla üretilmiş olabilir."
        else:
            score = 0.05
            fired = False
            detail = f"Normal EXIF: {exif_data.get(MAKE_TAG, '?')} {exif_data.get(MODEL_TAG, '?')}"

        result = {
            "score": round(score, 4),
            "fired": fired,
            "has_exif": True,
            "has_camera_info": has_make or has_model,
            "software": exif_data.get(SOFTWARE_TAG, None),
            "ai_tool_detected": ai_detected,
            "detail": detail
        }
    except Exception as e:
        result["detail"] = f"EXIF anomali hatası: {str(e)}"

    return result


# ---------------------------------------------------------------------------
# TEKNİK 6 — Renk Kanalı Tutarsızlığı (GAN Artifact)
# GAN görüntülerinde R/G/B kanallarının standart sapmaları arasındaki
# fark doğal görüntülerden belirgin şekilde sapabilir.
# ---------------------------------------------------------------------------
def _color_channel_analysis(img: "Image.Image") -> Dict[str, Any]:
    """
    RGB kanallarının istatistiksel tutarlılığını kontrol eder.
    """
    result = {"score": 0.0, "fired": False, "detail": "Renk kanalı analizi yapılamadı"}

    if not NUMPY_AVAILABLE:
        return result

    try:
        rgb = img.convert("RGB")
        arr = np.array(rgb, dtype=np.float32)
        r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]

        std_r, std_g, std_b = float(np.std(r)), float(np.std(g)), float(np.std(b))
        mean_r, mean_g, mean_b = float(np.mean(r)), float(np.mean(g)), float(np.mean(b))

        # Kanallar arası standart sapma farkı
        stds = [std_r, std_g, std_b]
        max_diff = max(stds) - min(stds)

        # Doğal fotoğraflarda kanallar arası std genellikle 30 birimden fazla farklı olmaz
        score = min(max_diff / 80.0, 1.0)
        fired = max_diff > 35.0

        # Kırmızı kanal baskınlığı (bazı deepfake ağları kırmızı kanala daha fazla artefakt bırakır)
        r_dominance = abs(std_r - (std_g + std_b) / 2)
        if r_dominance > 20:
            score = min(score + 0.15, 1.0)
            fired = True

        result = {
            "score": round(score, 4),
            "std_r": round(std_r, 2),
            "std_g": round(std_g, 2),
            "std_b": round(std_b, 2),
            "max_channel_diff": round(max_diff, 2),
            "fired": fired,
            "detail": f"Kanal Std Farkı: {max_diff:.1f} {'(ŞÜPHELİ: Anormal dağılım)' if fired else '(Normal)'}"
        }
    except Exception as e:
        result["detail"] = f"Renk kanalı hatası: {str(e)}"

    return result


# ---------------------------------------------------------------------------
# ANA FONKSİYON — Heuristic Deepfake Analizi
# ---------------------------------------------------------------------------
def analyze_deepfake_heuristic(file_path: str) -> Dict[str, Any]:
    """
    Görüntüyü 6 farklı heuristik teknikle analiz eder ve
    ağırlıklı deepfake olasılığı hesaplar.

    Args:
        file_path: Analiz edilecek dosyanın tam yolu.

    Returns:
        {
          "deepfake_probability": float (0.0-1.0),
          "confidence_score": float,
          "verdict": str,
          "indicators": list[str],
          "technique_results": dict,
          "status": str
        }
    """
    if not PIL_AVAILABLE or not NUMPY_AVAILABLE:
        return {
            "deepfake_probability": 0.0,
            "confidence_score": 0.0,
            "verdict": "ANALIZ_YAPILAMADI",
            "indicators": ["PIL veya NumPy kurulu değil"],
            "technique_results": {},
            "status": "missing_dependencies"
        }

    if not _is_image(file_path):
        return {
            "deepfake_probability": 0.0,
            "confidence_score": 0.0,
            "verdict": "GORUNTU_DEGIL",
            "indicators": ["Dosya bir görüntü formatında değil"],
            "technique_results": {},
            "status": "not_image"
        }

    if not os.path.exists(file_path):
        return {
            "deepfake_probability": 0.0,
            "confidence_score": 0.0,
            "verdict": "DOSYA_BULUNAMADI",
            "indicators": ["Belirtilen dosya yolu bulunamadı"],
            "technique_results": {},
            "status": "file_not_found"
        }

    try:
        img = Image.open(file_path)
        # Çok küçük dosyaları boyutlandır
        if img.width < 64 or img.height < 64:
            img = img.resize((64, 64))
    except Exception as e:
        return {
            "deepfake_probability": 0.0,
            "confidence_score": 0.0,
            "verdict": "GORUNTU_ACILAMADI",
            "indicators": [f"Görüntü açılamadı: {str(e)}"],
            "technique_results": {},
            "status": "open_error"
        }

    # Tüm teknikleri çalıştır
    ela = _ela_analysis(img)
    fft = _fft_analysis(img)
    dct = _dct_block_analysis(img)
    entropy = _entropy_inconsistency_analysis(img)
    exif_an = _exif_anomaly_analysis(file_path)
    color = _color_channel_analysis(img)

    # Ağırlıklı skor hesabı
    # ELA en güçlü gösterge; EXIF ve FFT ikinci; diğerleri destekleyici
    weights = {
        "ela":     0.28,
        "fft":     0.18,
        "dct":     0.15,
        "entropy": 0.17,
        "exif":    0.14,
        "color":   0.08
    }

    scores = {
        "ela":     ela.get("score", 0.0),
        "fft":     fft.get("score", 0.0),
        "dct":     dct.get("score", 0.0),
        "entropy": entropy.get("score", 0.0),
        "exif":    exif_an.get("score", 0.0),
        "color":   color.get("score", 0.0)
    }

    weighted_prob = sum(weights[k] * scores[k] for k in weights)

    # En az 2 teknik ateşlediyse çarpan ekle
    fired_count = sum(1 for t in [ela, fft, dct, entropy, exif_an, color] if t.get("fired"))

    if fired_count >= 4:
        weighted_prob = min(weighted_prob * 1.35, 0.99)
    elif fired_count == 3:
        weighted_prob = min(weighted_prob * 1.20, 0.97)
    elif fired_count == 2:
        weighted_prob = min(weighted_prob * 1.10, 0.92)

    # Güven skoru: kaç teknik çalıştı?
    active_techniques = sum(1 for t in [ela, fft, dct, entropy, exif_an, color]
                            if "yapılamadı" not in t.get("detail", "yapılamadı"))
    confidence = active_techniques / 6.0

    # Karar
    if weighted_prob >= 0.70:
        verdict = "DEEPFAKE"
    elif weighted_prob >= 0.45:
        verdict = "ŞÜPHELİ_DEEPFAKE"
    elif weighted_prob >= 0.25:
        verdict = "DÜŞÜK_ŞÜPHELİ"
    else:
        verdict = "NORMAL"

    # Uyarı listesi
    indicators = []
    if ela.get("fired"):
        indicators.append(f"ELA: Sıkıştırma tutarsızlığı — {ela.get('detail')}")
    if fft.get("fired"):
        indicators.append(f"FFT: Anormal frekans dağılımı — {fft.get('detail')}")
    if dct.get("fired"):
        indicators.append(f"DCT: Heterojen blok yapısı — {dct.get('detail')}")
    if entropy.get("fired"):
        indicators.append(f"Entropi: Merkez-kenar tutarsızlığı — {entropy.get('detail')}")
    if exif_an.get("fired"):
        indicators.append(f"EXIF: Metadata anomalisi — {exif_an.get('detail')}")
    if color.get("fired"):
        indicators.append(f"Renk: Kanal dağılımı anormal — {color.get('detail')}")

    if not indicators:
        indicators.append("Hiçbir teknik belirgin anomali tespit etmedi.")

    return {
        "deepfake_probability": round(weighted_prob, 4),
        "confidence_score": round(confidence, 4),
        "verdict": verdict,
        "fired_techniques": fired_count,
        "active_techniques": active_techniques,
        "indicators": indicators,
        "technique_results": {
            "ela": ela,
            "fft": fft,
            "dct": dct,
            "entropy_inconsistency": entropy,
            "exif_anomaly": exif_an,
            "color_channels": color
        },
        "is_stego_suspect": entropy.get("fired", False) and ela.get("fired", False),
        "entropy_score": round(entropy.get("center_entropy", 0.0), 4),
        "status": "success"
    }
