import os
import cv2
import numpy as np
from PIL import Image

def analyze_fft(image_path: str, output_path: str) -> dict:
    """
    Görsele 2D Fast Fourier Transform (FFT) uygular.
    Frekans spektrumunu çıkararak yapay zeka üretimi (GAN/Diffusion) veya
    piksel kopyalama artefaktlarını analiz eder.

    :param image_path: Girdi görselinin dosya yolu.
    :param output_path: Spektrum görselinin kaydedileceği dosya yolu.
    :return: Analiz sonuçlarını içeren sözlük.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Girdi görseli bulunamadı: {image_path}")

    # Görseli gri tonlamalı oku
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        pil_img = Image.open(image_path).convert("L")
        img = np.array(pil_img)

    # 2D Fast Fourier Transform
    f = np.fft.fft2(img)
    fshift = np.fft.fftshift(f)

    # Genlik Spektrumu (Magnitude Spectrum)
    magnitude_spectrum = 20 * np.log(np.abs(fshift) + 1e-8)

    # Spektrumu 0-255 aralığına normalize et
    norm_spectrum = cv2.normalize(magnitude_spectrum, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)

    # Yüksek frekans gürültü analizi (Merkez dışındaki bileşenlerin oranı)
    h, w = norm_spectrum.shape
    cy, cx = h // 2, w // 2
    r = min(h, w) // 8  # Düşük frekans merkez yarıçapı

    # Merkez dışı maske
    y, x = np.ogrid[:h, :w]
    dist_from_center = np.sqrt((x - cx)**2 + (y - cy)**2)
    high_freq_mask = dist_from_center > r

    high_freq_energy = float(np.mean(norm_spectrum[high_freq_mask]))
    total_energy = float(np.mean(norm_spectrum))
    hf_noise_ratio = round(high_freq_energy / (total_energy + 1e-8), 4)

    # Diske görsel olarak kaydet
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    cv2.imwrite(output_path, norm_spectrum)

    # Sentetik/AI görsel şüphesi skoru
    is_synthetic_suspect = bool(hf_noise_ratio > 0.85 or hf_noise_ratio < 0.25)

    return {
        "fft_spectrum_path": output_path,
        "high_freq_noise_ratio": hf_noise_ratio,
        "total_energy": round(total_energy, 2),
        "is_synthetic_suspect": is_synthetic_suspect
    }
