"""
Forensic Vision - Dosya Oyma (File Carver) & Gömülü Yük Tespit Modülü
Görsellerin EOF (End of File) sınırından sonra gizlenmiş / iliştirilmiş (appended payload)
verileri, polyglot dosyaları, gömülü ZIP/RAR arşivlerini ve çalıştırılabilir kodları tespit eder.
Binwalk ve adli bilişim 'File Carving' prensiplerine göre çalışır.
"""

import os
import math
from typing import Dict, Any, List, Tuple, Optional

# Gömülü dosya imza kalıpları
PAYLOAD_SIGNATURES = [
    (b"PK\x03\x04", "ZIP Arşivi (Local File Header)", "ZIP"),
    (b"PK\x05\x06", "ZIP Arşivi (End of Central Directory)", "ZIP"),
    (b"Rar!\x1a\x07\x00", "RAR v4 Arşivi", "RAR"),
    (b"Rar!\x1a\x07\x01\x00", "RAR v5 Arşivi", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Arşivi", "7Z"),
    (b"MZ", "Windows PE Executable / DLL (MZ Header)", "EXE"),
    (b"\x7fELF", "Linux ELF Binary", "ELF"),
    (b"%PDF-", "Gömülü PDF Belgesi", "PDF"),
    (b"BZh", "Bzip2 Sıkıştırılmış Arşiv", "BZIP2"),
    (b"\x1f\x8b\x08", "Gzip Sıkıştırılmış Veri", "GZIP"),
    (b"powershell", "PowerShell Komut Kalıbı", "SCRIPT"),
    (b"cmd.exe", "Windows Komut Satırı İzi", "SCRIPT"),
    (b"<?php", "PHP Web Shell Kodu", "WEBSHELL"),
]


def calculate_entropy(data: bytes) -> float:
    """
    Verilen byte dizisinin Shannon Entropisini hesaplar (0.0 - 8.0).
    8.0'a yakın değerler şifrelenmiş veya sıkıştırılmış zararlı yüke işaret eder.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def find_jpeg_eof(data: bytes) -> Optional[int]:
    """
    JPEG dosyasının gerçek EOI (End of Image - FF D9) işaretçisinin bittiği offset'i bulur.
    Birden fazla FF D9 olması durumunda (küçük resim vb.), dosya sonuna en yakın geçerli olanı tespit eder.
    """
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None

    # Son FF D9 pozisyonunu ara
    pos = data.rfind(b"\xff\xd9")
    if pos != -1:
        return pos + 2  # FF D9 2 byte'tır, sonrasındaki ilk byte offset'i
    return None


def find_png_eof(data: bytes) -> Optional[int]:
    """
    PNG dosyasının IEND chunk'ının bittiği offset'i bulur.
    Format: 4 bytes length (00 00 00 00) + 4 bytes type ('IEND') + 4 bytes CRC
    """
    iend_pos = data.rfind(b"IEND")
    if iend_pos != -1:
        # IEND'den sonra 4 byte CRC gelir
        return iend_pos + 4 + 4
    return None


def find_gif_eof(data: bytes) -> Optional[int]:
    """
    GIF dosyasının bitiş karakteri olan ';' (0x3B) offset'ini bulur.
    """
    trailer_pos = data.rfind(b"\x3b")
    if trailer_pos != -1:
        return trailer_pos + 1
    return None


def find_pdf_eof(data: bytes) -> Optional[int]:
    """
    PDF dosyasının %%EOF işaretçisini bulur.
    """
    eof_pos = data.rfind(b"%%EOF")
    if eof_pos != -1:
        # %%EOF sonrasındaki newline karakterlerini de tüket
        end = eof_pos + 5
        while end < len(data) and data[end] in (b"\r"[0], b"\n"[0], b" "[0]):
            end += 1
        return end
    return None


def scan_for_signatures(data: bytes, base_offset: int = 0) -> List[Dict[str, Any]]:
    """
    Byte verisi içinde bilinen dosya / arşiv / zararlı kod imzalarını tarar.
    """
    findings = []
    for sig, desc, sig_type in PAYLOAD_SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break

            # Özel PE Executable doğrulaması (Sadece MZ yetmez, e_lfanew offset'inde PE var mı?)
            if sig == b"MZ":
                if idx + 64 <= len(data):
                    try:
                        e_lfanew = int.from_bytes(data[idx + 60 : idx + 64], byteorder="little")
                        if idx + e_lfanew + 4 <= len(data) and data[idx + e_lfanew : idx + e_lfanew + 4] == b"PE\x00\x00":
                            findings.append({
                                "signature": "PE (Portable Executable)",
                                "type": "EXE",
                                "offset": base_offset + idx,
                                "description": "Doğrulanmış Windows Çalıştırılabilir Dosyası (PE/EXE)",
                                "hex_offset": hex(base_offset + idx)
                            })
                    except Exception:
                        pass
                start = idx + 1
                continue

            findings.append({
                "signature": sig.hex().upper(),
                "type": sig_type,
                "offset": base_offset + idx,
                "description": desc,
                "hex_offset": hex(base_offset + idx)
            })
            start = idx + len(sig)

    return findings


def detect_appended_payload(file_path: str) -> Dict[str, Any]:
    """
    Görselin EOF işaretçisinden sonra fazladan iliştirilmiş veri (appended data)
    veya gömülü .zip/.rar/çalıştırılabilir yük olup olmadığını analiz eder.

    :param file_path: İncelenecek dosyanın yolu.
    :return: File Carving adli analiz raporu sözlüğü.
    """
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "message": f"Dosya bulunamadı: {file_path}",
            "payload_detected": False
        }

    total_size = os.path.getsize(file_path)
    if total_size == 0:
        return {
            "status": "warning",
            "file_size": 0,
            "has_appended_data": False,
            "payload_detected": False,
            "details": "Boş dosya."
        }

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # Format tespit ve EOF offset'i belirleme
    file_type = "UNKNOWN"
    eof_offset = None

    if file_bytes.startswith(b"\xff\xd8"):
        file_type = "JPEG"
        eof_offset = find_jpeg_eof(file_bytes)
    elif file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        file_type = "PNG"
        eof_offset = find_png_eof(file_bytes)
    elif file_bytes.startswith(b"GIF87a") or file_bytes.startswith(b"GIF89a"):
        file_type = "GIF"
        eof_offset = find_gif_eof(file_bytes)
    elif file_bytes.startswith(b"%PDF"):
        file_type = "PDF"
        eof_offset = find_pdf_eof(file_bytes)

    has_appended_data = False
    appended_length = 0
    appended_entropy = 0.0
    appended_signatures = []
    payload_detected = False
    threat_level = "CLEAN"
    threat_score = 0
    details = ""

    # Tüm dosyadaki gömülü imzaları ara
    all_signatures = scan_for_signatures(file_bytes)

    if eof_offset is not None and eof_offset < total_size:
        appended_length = total_size - eof_offset
        # Tolerans: JPEG dosyalarında bazen 1-2 byte trailing 0x00 veya 0xFF olabilir.
        if appended_length > 2:
            has_appended_data = True
            appended_bytes = file_bytes[eof_offset:]
            appended_entropy = calculate_entropy(appended_bytes)

            # Sadece iliştirilmiş kısımda imza ara
            appended_signatures = scan_for_signatures(appended_bytes, base_offset=eof_offset)

            if appended_signatures:
                payload_detected = True
                threat_level = "CRITICAL"
                threat_score = 95
                sig_names = ", ".join(s["description"] for s in appended_signatures)
                details = (
                    f"KRİTİK TEHDİT: Görselin dosya sonundan (EOF offset: {hex(eof_offset)}) sonra "
                    f"{appended_length} byte boyutunda gömülü yük tespit edildi! "
                    f"Tespit edilen içerik: {sig_names}. Entropi: {appended_entropy}/8.0."
                )
            else:
                # İmza yok ama yüksek entropili veya şüpheli veri iliştirilmiş
                payload_detected = True
                threat_score = 75 if appended_entropy > 7.0 else 50
                threat_level = "HIGH" if appended_entropy > 7.0 else "MEDIUM"
                details = (
                    f"ŞÜPHELİ VERİ: Görselin bittiği noktadan sonra {appended_length} byte fazladan veri bulundu. "
                    f"Veri entropisi ({appended_entropy}/8.0) {'şifrelenmiş/sıkıştırılmış' if appended_entropy > 7.0 else 'düz metin'} "
                    f"bir taşıyıcı yüke işaret ediyor."
                )
    elif eof_offset is None:
        # Standart EOF bulunamadı veya format tam tanınmadı
        if all_signatures:
            payload_detected = True
            threat_level = "HIGH"
            threat_score = 70
            details = f"Dosya yapısı içinde şüpheli ikili imzalar bulundu: {[s['description'] for s in all_signatures]}"
        else:
            details = f"{file_type} dosya sınırları standartlara uygun, ek veri tespit edilmedi."
    else:
        # Temiz dosya
        details = (
            f"Dosya bütünlüğü kusursuz. {file_type} resmi format sınırları ({total_size} byte) içinde sonlanıyor. "
            f"Dosya sonuna eklenmiş veri (Overlay/Appended Payload) bulunamadı."
        )

    return {
        "status": "success",
        "file_path": file_path,
        "file_type": file_type,
        "total_file_size": total_size,
        "eof_offset": eof_offset,
        "has_appended_data": has_appended_data,
        "appended_bytes_length": appended_length,
        "appended_entropy": appended_entropy,
        "appended_signatures": appended_signatures,
        "all_embedded_signatures": all_signatures,
        "payload_detected": payload_detected,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "details": details
    }


if __name__ == "__main__":
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else __file__
    print(detect_appended_payload(test_path))
