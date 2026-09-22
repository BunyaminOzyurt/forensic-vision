import os
import math
import cv2
import numpy as np
from PIL import Image

def extract_bit_planes(image_path: str, output_path: str) -> str:
    """
    Görselin 0-7 arası LSB/MSB bit katmanlarını (Bit Planes) ayıklar
    ve 2x4 grid şeklinde görselleştirerek kaydeder.
    LSB (0. ve 1. bit) katmanları gizli steganografi verilerini ortaya çıkarır.

    :param image_path: Girdi görselinin dosya yolu.
    :param output_path: Bit katmanları görselinin kaydedileceği dosya yolu.
    :return: Kaydedilen görselin dosya yolu.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Girdi görseli bulunamadı: {image_path}")

    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        pil_img = Image.open(image_path).convert("L")
        img = np.array(pil_img)

    h, w = img.shape
    planes = []

    for bit in range(8):
        # Bit plane maskeleme
        bit_plane = (img >> bit) & 1
        # 0 veya 255 görselleştirmesi
        bit_plane_img = (bit_plane * 255).astype(np.uint8)
        planes.append(bit_plane_img)

    # 2x4 Grid Oluştur
    top_row = np.hstack(planes[4:8])   # Bit 4, 5, 6, 7 (MSB)
    bottom_row = np.hstack(planes[0:4]) # Bit 0, 1, 2, 3 (LSB)
    composite = np.vstack([top_row, bottom_row])

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    cv2.imwrite(output_path, composite)

    return output_path

def calculate_shannon_entropy(image_path: str) -> float:
    """
    Görselin piksel yoğunluğu Shannon Entropisini hesaplar (0.0 - 8.0).
    > 7.9 olan yüksek entropiler şifrelenmiş/steganografi gizlenmiş veri şüphesini işaret eder.

    :param image_path: Girdi görselinin dosya yolu.
    :return: Entropi değeri (float).
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Girdi görseli bulunamadı: {image_path}")

    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        pil_img = Image.open(image_path).convert("L")
        img = np.array(pil_img)

    # Histogram hesabı
    hist = cv2.calcHist([img], [0], None, [256], [0, 256]).ravel()
    total_pixels = img.size

    # Olasılıklar ve Entropi (Shannon)
    entropy = 0.0
    for count in hist:
        if count > 0:
            p = count / total_pixels
            entropy -= p * math.log2(p)

    return round(entropy, 4)
