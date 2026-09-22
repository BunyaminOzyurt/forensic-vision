import os
from io import BytesIO
import numpy as np
from PIL import Image, ImageChops, ImageEnhance

def generate_ela(image_path: str, output_path: str, quality: int = 90, scale: float = 15.0) -> tuple[np.ndarray, str, float]:
    """
    Error Level Analysis (ELA) hesabı yapar.
    Görseli belirtilen JPEG kalitesinde bellekte tekrar kaydeder ve orijinal
    görsel ile piksel farkını alarak manipüle edilmiş alanları ısı haritası olarak çıkarır.

    :param image_path: Girdi görselinin dosya yolu.
    :param output_path: ELA sonucunun kaydedileceği dosya yolu.
    :param quality: Re-compression JPEG kalitesi (Varsayılan: 90).
    :param scale: Fark görünürlüğünü artırma katsayısı (Varsayılan: 15.0).
    :return: (ELA numpy dizisi, ELA görsel kaydedilme yolu, ortalama ELA manipülasyon skoru)
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Girdi görseli bulunamadı: {image_path}")

    # Görseli aç ve RGB'ye dönüştür
    original_img = Image.open(image_path).convert("RGB")

    # Görseli bellekte (BytesIO) belirtilen kalitede yeniden JPEG olarak kaydet
    buffer = BytesIO()
    original_img.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)

    resaved_img = Image.open(buffer).convert("RGB")

    # İki görsel arasındaki piksel farkını al
    ela_img = ImageChops.difference(original_img, resaved_img)

    # Farkı daha belirgin hale getirmek için ölçeklendir (Enhance)
    extrema = ela_img.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0:
        max_diff = 1

    scale_factor = scale if scale > 0 else (255.0 / max_diff)
    enhancer = ImageEnhance.Brightness(ela_img)
    ela_img = enhancer.enhance(scale_factor)

    # Dizine kaydet
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    ela_img.save(output_path)

    # Numpy array ve ortalama ELA skoru hesaplama
    ela_np = np.array(ela_img)
    mean_score = float(np.mean(ela_np))

    return ela_np, output_path, round(mean_score, 4)
