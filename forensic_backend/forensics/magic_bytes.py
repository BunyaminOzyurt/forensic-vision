"""
Forensic Vision - Magic Bytes & Dosya Bütünlüğü Doğrulayıcı
Bu modül dosyanın ham ikili başlıklarını (magic bytes / file header) okuyarak
dosyanın gerçek türünü tespit eder ve beyan edilen dosya uzantısı ile karşılaştırır.
Uzantı yanıltması (Extension Spoofing / Polyglot) saldırılarını tespit eder.
"""

import os
from typing import Dict, Any, Tuple, Optional

# Bilinen dosya imzaları sözlüğü (Signature Table)
# (Hex prefix, Format Adı, MIME Türü, Geçerli Uzantılar)
KNOWN_SIGNATURES = [
    # JPEG Ailesi
    (bytes.fromhex("FFD8FFE0"), "JPEG (JFIF)", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8FFE1"), "JPEG (EXIF)", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8FFE2"), "JPEG (CIFF)", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8FFE3"), "JPEG (SPIFF)", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8FFE8"), "JPEG (SPIFF)", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8FFDB"), "JPEG (Raw)", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8FFEE"), "JPEG", "image/jpeg", [".jpg", ".jpeg"]),
    (bytes.fromhex("FFD8"), "JPEG", "image/jpeg", [".jpg", ".jpeg"]),

    # PNG
    (bytes.fromhex("89504E470D0A1A0A"), "PNG", "image/png", [".png"]),

    # GIF
    (bytes.fromhex("474946383761"), "GIF87a", "image/gif", [".gif"]),
    (bytes.fromhex("474946383961"), "GIF89a", "image/gif", [".gif"]),

    # BMP
    (bytes.fromhex("424D"), "BMP", "image/bmp", [".bmp"]),

    # TIFF
    (bytes.fromhex("49492A00"), "TIFF (Little Endian)", "image/tiff", [".tif", ".tiff"]),
    (bytes.fromhex("4D4D002A"), "TIFF (Big Endian)", "image/tiff", [".tif", ".tiff"]),

    # PDF
    (bytes.fromhex("25504446"), "PDF", "application/pdf", [".pdf"]),

    # ZIP ve Arşivler (Office docx/xlsx, APK, JAR dahil)
    (bytes.fromhex("504B0304"), "ZIP Archive", "application/zip", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (bytes.fromhex("504B0506"), "ZIP Archive (Empty)", "application/zip", [".zip"]),
    (bytes.fromhex("504B0708"), "ZIP Archive (Spanned)", "application/zip", [".zip"]),

    # RAR
    (bytes.fromhex("526172211A0700"), "RAR Archive (v4)", "application/x-rar-compressed", [".rar"]),
    (bytes.fromhex("526172211A070100"), "RAR Archive (v5)", "application/x-rar-compressed", [".rar"]),

    # 7-Zip
    (bytes.fromhex("377ABCAF271C"), "7-Zip Archive", "application/x-7z-compressed", [".7z"]),

    # Windows PE (Portable Executable - EXE, DLL, SYS)
    (bytes.fromhex("4D5A"), "Windows PE Executable / DLL", "application/x-dosexec", [".exe", ".dll", ".sys", ".scr"]),

    # Linux ELF Executable
    (bytes.fromhex("7F454C46"), "Linux ELF Executable", "application/x-executable", ["", ".elf", ".bin"]),
]


def identify_format(header_bytes: bytes) -> Tuple[Optional[str], Optional[str], list]:
    """
    İlk byte dizisini analiz ederek tespit edilen formatı, MIME türünü ve geçerli uzantıları döndürür.
    WebP gibi özel offset gerektiren formatları da kontrol eder.
    """
    # Özel durum: WebP (RIFF....WEBP)
    if len(header_bytes) >= 12 and header_bytes[:4] == b"RIFF" and header_bytes[8:12] == b"WEBP":
        return "WEBP", "image/webp", [".webp"]

    for sig, fmt, mime, valid_exts in KNOWN_SIGNATURES:
        if header_bytes.startswith(sig):
            return fmt, mime, valid_exts

    return "Bilinmeyen İkili Format", "application/octet-stream", []


def verify_file_integrity(file_path: str) -> Dict[str, Any]:
    """
    Dosyanın ilk 16 byte'ını okuyarak dosya başlığını (Magic Bytes) denetler.
    Gerçek MIME türü ile beyan edilen uzantıyı karşılaştırarak sahte uzantı
    (spoofing) saldırılarını tespit eder.

    :param file_path: İncelenecek dosyanın mutlak veya göreceli yolu.
    :return: Adli bilişim doğrulama sonuç sözlüğü.
    """
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "message": f"Dosya bulunamadı: {file_path}",
            "spoof_detected": False
        }

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return {
            "status": "warning",
            "file_path": file_path,
            "file_size": 0,
            "spoof_detected": True,
            "details": "Dosya boyutu 0 byte (boş dosya). Adli delil bütünlüğü doğrulanamadı."
        }

    # Dosyanın ilk 32 byte'ını oku (16 byte hex dökümü + özel kontroller için)
    with open(file_path, "rb") as f:
        header_32 = f.read(32)

    header_16 = header_32[:16]
    magic_hex_16 = header_16.hex().upper()
    magic_hex_spaced = " ".join(magic_hex_16[i:i+2] for i in range(0, len(magic_hex_16), 2))

    # Uzantıyı al (.jpg, .png vb.)
    _, ext = os.path.splitext(file_path)
    declared_extension = ext.lower().strip()

    detected_format, detected_mime, valid_exts = identify_format(header_32)

    spoof_detected = False
    threat_level = "CLEAN"
    threat_score = 0
    details = ""

    if detected_format == "Bilinmeyen İkili Format":
        # Bilinmeyen başlık
        spoof_detected = True
        threat_level = "MEDIUM"
        threat_score = 45
        details = (
            f"Dosya başlığı ({magic_hex_spaced[:23]}) bilinen güvenli görsel formatları ile eşleşmedi. "
            f"Beyan edilen uzantı: '{declared_extension}'."
        )
    elif declared_extension in valid_exts:
        # Uzantı ve başlık tam uyumlu
        spoof_detected = False
        threat_level = "CLEAN"
        threat_score = 0
        details = (
            f"Dosya başlığı (Magic Bytes) beyan edilen uzantı '{declared_extension}' ile tam uyumlu: "
            f"{detected_format} ({detected_mime})."
        )
    else:
        # Uzantı yanıltması tespit edildi!
        spoof_detected = True
        threat_score = 90
        threat_level = "CRITICAL" if "Executable" in detected_format or "ZIP" in detected_format else "HIGH"
        details = (
            f"DİKKAT: Uzantı Yanıltması (Spoofing) Tespit Edildi! Dosya '{declared_extension}' uzantısına sahip "
            f"görünmesine rağmen, ham dosya başlığı '{detected_format}' ({detected_mime}) olduğunu kanıtlamaktadır. "
            f"Zararlı kod taşıma veya dosya filtrelerini atlatma girişimi olabilir."
        )

    return {
        "status": "success",
        "file_path": file_path,
        "file_size": file_size,
        "declared_extension": declared_extension,
        "magic_hex_16": magic_hex_16,
        "magic_hex_spaced": magic_hex_spaced,
        "detected_format": detected_format,
        "detected_mime": detected_mime,
        "valid_extensions": valid_exts,
        "spoof_detected": spoof_detected,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "details": details
    }


if __name__ == "__main__":
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else __file__
    print(verify_file_integrity(test_path))
