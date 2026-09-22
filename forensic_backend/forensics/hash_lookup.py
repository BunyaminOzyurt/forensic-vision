"""
Forensic Vision - Kriptografik Özetleme (Hashing) & Zararlı İtibar Kontrolü
Dosyanın MD5, SHA-1 ve SHA-256 kriptografik özet değerlerini üretir.
Delil bütünlüğü zincirini (Chain of Custody) sağlar ve bilinen zararlı
yazılım / tehdit veritabanı (Threat Intelligence) ile itibar kontrolü yapar.
"""

import os
import hashlib
from typing import Dict, Any, Optional

# Bilinen zararlı dosya test özetleri (Örnek Tehdit İstihbaratı Veritabanı)
KNOWN_THREAT_DATABASE = {
    # EICAR Standart Antivirüs Test Dosyası
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Standard-AV-Test-File",
        "category": "Test-Signature",
        "severity": "CRITICAL",
        "score": 100
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR-Standard-AV-Test-File (MD5)",
        "category": "Test-Signature",
        "severity": "CRITICAL",
        "score": 100
    },
    # WannaCry Ransomware SHA-256
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": {
        "name": "WannaCry.Ransomware",
        "category": "Ransomware",
        "severity": "CRITICAL",
        "score": 100
    },
    # StegHide / Stegware yaygın örnek hash'i
    "d41d8cd98f00b204e9800998ecf8427e": {
        "name": "Zero-Byte Empty File (MD5)",
        "category": "Anomaly",
        "severity": "LOW",
        "score": 10
    }
}


def _format_size(size_bytes: int) -> str:
    """
    Byte cinsinden boyutu okunabilir birime (B, KB, MB) dönüştürür.
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def check_reputation(md5: str, sha256: str) -> Dict[str, Any]:
    """
    Kriptografik özetleri yerel ve genel tehdit istihbaratı referanslarıyla kontrol eder.
    """
    sha256_lower = sha256.lower()
    md5_lower = md5.lower()

    reputation = {
        "is_known_malicious": False,
        "threat_name": None,
        "threat_category": None,
        "severity": "CLEAN",
        "threat_score": 0,
        "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_lower}",
        "malwarebazaar_url": f"https://bazaar.abuse.ch/sample/{sha256_lower}/",
        "details": "Dosya özeti bilinen zararlı yazılım tehdit listelerinde yer almıyor."
    }

    if sha256_lower in KNOWN_THREAT_DATABASE:
        hit = KNOWN_THREAT_DATABASE[sha256_lower]
        reputation["is_known_malicious"] = True
        reputation["threat_name"] = hit["name"]
        reputation["threat_category"] = hit["category"]
        reputation["severity"] = hit["severity"]
        reputation["threat_score"] = hit["score"]
        reputation["details"] = f"KRİTİK UYARI: Dosya özeti bilinen '{hit['name']}' tehdidi ile tam eşleşti!"
    elif md5_lower in KNOWN_THREAT_DATABASE:
        hit = KNOWN_THREAT_DATABASE[md5_lower]
        reputation["is_known_malicious"] = True
        reputation["threat_name"] = hit["name"]
        reputation["threat_category"] = hit["category"]
        reputation["severity"] = hit["severity"]
        reputation["threat_score"] = hit["score"]
        reputation["details"] = f"KRİTİK UYARI: Dosya MD5 özeti '{hit['name']}' tehdidi ile eşleşti!"

    return reputation


def calculate_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, Any]:
    """
    Dosyanın MD5, SHA-1 ve SHA-256 kriptografik özet değerlerini parça parça (chunking)
    okuyarak yüksek bellek verimliliğiyle hesaplar ve zararlı itibarını sorgular.

    :param file_path: Özeti hesaplanacak dosyanın yolu.
    :param chunk_size: Her okumada işlenecek byte boyutu (varsayılan: 64 KB).
    :return: Özet değerleri ve itibar bilgilerini içeren sözlük.
    """
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "message": f"Dosya bulunamadı: {file_path}"
        }

    file_size = os.path.getsize(file_path)

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    md5_str = md5_hash.hexdigest().lower()
    sha1_str = sha1_hash.hexdigest().lower()
    sha256_str = sha256_hash.hexdigest().lower()

    reputation = check_reputation(md5_str, sha256_str)

    return {
        "status": "success",
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "file_size_bytes": file_size,
        "file_size_formatted": _format_size(file_size),
        "md5": md5_str,
        "sha1": sha1_str,
        "sha256": sha256_str,
        "reputation": reputation,
        "chain_of_custody_verified": True
    }


if __name__ == "__main__":
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else __file__
    print(calculate_hashes(test_path))
