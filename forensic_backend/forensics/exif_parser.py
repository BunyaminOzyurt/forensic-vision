"""
Forensic Vision - EXIF Metadata & GPS Analiz Modülü
Görsel dosyalarındaki EXIF üst verilerini çıkarır, kamera donanımı, çekim zamanı,
Photoshop/GIMP gibi yazılımsal manipülasyon izlerini ve GPS coğrafi konumunu tespit eder.
"""

import os
from typing import Dict, Any, Optional, Tuple
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# Bilinen manipülasyon / görsel düzenleme yazılımları anahtar kelimeleri
EDITING_SOFTWARE_KEYWORDS = [
    "photoshop", "gimp", "canva", "lightroom", "paint.net", "snapseed",
    "pixlr", "affinity", "corel", "procreate", "befunky", "fotor",
    "vsco", "facetune", "afterlight", "picsart", "krita"
]


def _convert_to_float(value: Any) -> Optional[float]:
    """
    IFDRational veya tuple/list halindeki rasyonel değerleri güvenle float'a dönüştürür.
    """
    if value is None:
        return None
    try:
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            return float(value.numerator) / float(value.denominator) if value.denominator != 0 else 0.0
        if isinstance(value, (tuple, list)) and len(value) == 2:
            return float(value[0]) / float(value[1]) if value[1] != 0 else 0.0
        return float(value)
    except Exception:
        return None


def _dms_to_decimal(dms_values: Any, ref: str) -> Optional[float]:
    """
    EXIF GPS (Derece, Dakika, Saniye) değerlerini ondalık dereceye (Decimal Degrees) dönüştürür.
    """
    if not dms_values or len(dms_values) < 3:
        return None

    try:
        degrees = _convert_to_float(dms_values[0]) or 0.0
        minutes = _convert_to_float(dms_values[1]) or 0.0
        seconds = _convert_to_float(dms_values[2]) or 0.0

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if ref.upper() in ["S", "W"]:
            decimal = -decimal

        return round(decimal, 6)
    except Exception:
        return None


def _parse_gps_info(gps_dict: dict) -> Dict[str, Any]:
    """
    GPS alt sözlüğünü adli bilişim formatında işler.
    """
    parsed_gps = {
        "has_gps": False,
        "latitude": None,
        "longitude": None,
        "altitude_meters": None,
        "maps_url": None,
        "coordinates_str": None
    }

    if not gps_dict:
        return parsed_gps

    # Tag id'lerini GPSTAGS isimlerine çevir
    named_gps = {}
    for k, v in gps_dict.items():
        sub_tag = GPSTAGS.get(k, k)
        named_gps[sub_tag] = v

    lat_dms = named_gps.get("GPSLatitude")
    lat_ref = str(named_gps.get("GPSLatitudeRef", "N"))
    lon_dms = named_gps.get("GPSLongitude")
    lon_ref = str(named_gps.get("GPSLongitudeRef", "E"))

    if lat_dms and lon_dms:
        lat = _dms_to_decimal(lat_dms, lat_ref)
        lon = _dms_to_decimal(lon_dms, lon_ref)

        if lat is not None and lon is not None:
            parsed_gps["has_gps"] = True
            parsed_gps["latitude"] = lat
            parsed_gps["longitude"] = lon
            parsed_gps["coordinates_str"] = f"{lat}, {lon}"
            parsed_gps["maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"

    alt_val = named_gps.get("GPSAltitude")
    if alt_val is not None:
        alt_meters = _convert_to_float(alt_val)
        if alt_meters is not None:
            parsed_gps["altitude_meters"] = round(alt_meters, 2)

    return parsed_gps


def extract_exif(file_path: str) -> Dict[str, Any]:
    """
    Verilen görsel dosyasının EXIF üst verilerini çıkarır ve adli analizini yapar.

    :param file_path: İncelenecek görselin dosya yolu.
    :return: Yapılandırılmış EXIF adli analiz sözlüğü.
    """
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "message": f"Dosya bulunamadı: {file_path}",
            "exif_found": False
        }

    result = {
        "status": "success",
        "file_path": file_path,
        "exif_found": False,
        "camera_make": "Bilinmiyor",
        "camera_model": "Bilinmiyor",
        "lens_model": "Bilinmiyor",
        "date_time_original": "Bilinmiyor",
        "date_time_digitized": "Bilinmiyor",
        "software": "Bilinmiyor",
        "software_tampering_suspect": False,
        "tampering_software": None,
        "gps": {
            "has_gps": False,
            "latitude": None,
            "longitude": None,
            "altitude_meters": None,
            "maps_url": None,
            "coordinates_str": None
        },
        "all_tags": {},
        "details": ""
    }

    try:
        with Image.open(file_path) as img:
            raw_exif = None
            if hasattr(img, "_getexif"):
                raw_exif = img._getexif()

            if not raw_exif:
                result["details"] = (
                    "EXIF üst verisi bulunamadı. Dosya üst verileri daha önce temizlenmiş (stripped) "
                    "veya sosyal medya platformları tarafından kaldırılmış olabilir."
                )
                return result

            result["exif_found"] = True
            all_tags_clean = {}
            gps_raw = None

            for tag_id, value in raw_exif.items():
                tag_name = TAGS.get(tag_id, str(tag_id))

                if tag_name == "GPSInfo":
                    gps_raw = value
                    continue

                # JSON serileştirilebilir hale getir
                if isinstance(value, bytes):
                    try:
                        clean_val = value.decode("utf-8", errors="replace").strip("\x00 \t\r\n")
                    except Exception:
                        clean_val = f"<Binary Data: {len(value)} bytes>"
                elif hasattr(value, "numerator") and hasattr(value, "denominator"):
                    clean_val = _convert_to_float(value)
                else:
                    clean_val = str(value).strip("\x00 \t\r\n")

                all_tags_clean[tag_name] = clean_val

            result["all_tags"] = all_tags_clean

            # Kamera & Cihaz Bilgileri
            result["camera_make"] = all_tags_clean.get("Make", "Bilinmiyor")
            result["camera_model"] = all_tags_clean.get("Model", "Bilinmiyor")
            result["lens_model"] = all_tags_clean.get("LensModel", all_tags_clean.get("LensInfo", "Bilinmiyor"))

            # Tarih Bilgileri
            result["date_time_original"] = all_tags_clean.get("DateTimeOriginal", all_tags_clean.get("DateTime", "Bilinmiyor"))
            result["date_time_digitized"] = all_tags_clean.get("DateTimeDigitized", "Bilinmiyor")

            # Yazılım İncelemesi (Photoshop, GIMP vb. manipülasyon izleri)
            software_entry = all_tags_clean.get("Software", "") or all_tags_clean.get("ProcessingSoftware", "")
            result["software"] = software_entry if software_entry else "Tespit Edilemedi"

            if software_entry:
                software_lower = software_entry.lower()
                for keyword in EDITING_SOFTWARE_KEYWORDS:
                    if keyword in software_lower:
                        result["software_tampering_suspect"] = True
                        result["tampering_software"] = software_entry
                        break

            # GPS Bilgilerini Ayrıştır
            if gps_raw:
                result["gps"] = _parse_gps_info(gps_raw)

            # Detaylı Değerlendirme Metni
            notes = []
            if result["camera_make"] != "Bilinmiyor" or result["camera_model"] != "Bilinmiyor":
                notes.append(f"Cihaz: {result['camera_make']} {result['camera_model']}.")
            if result["date_time_original"] != "Bilinmiyor":
                notes.append(f"Çekim Tarihi: {result['date_time_original']}.")
            if result["software_tampering_suspect"]:
                notes.append(f"DİKKAT: Düzenleme yazılımı izi tespit edildi ({result['tampering_software']}).")
            if result["gps"]["has_gps"]:
                notes.append(f"GPS Konumu: {result['gps']['coordinates_str']}.")

            result["details"] = " ".join(notes) if notes else "EXIF verileri mevcut ancak sınırlı bilgi içeriyor."

    except Exception as e:
        result["status"] = "error"
        result["message"] = f"EXIF verisi okunurken hata oluştu: {str(e)}"

    return result


if __name__ == "__main__":
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else __file__
    print(extract_exif(test_path))
