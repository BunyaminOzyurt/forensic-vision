import os
import json
import numpy as np
from PIL import Image, ImageDraw
from cv_engine import ForensicCVEngine

def create_synthetic_test_image(filename: str = "sample_test.jpg"):
    """
    Test amaçlı sentetik bir görsel (renkli daireler, metin ve gürültü içeren) üretir.
    """
    width, height = 400, 400
    # Arka plan gradyanı
    image = Image.new("RGB", (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(image)

    # Şekiller çiz
    draw.rectangle([50, 50, 200, 200], fill=(220, 50, 50), outline=(0, 0, 0))
    draw.ellipse([180, 180, 350, 350], fill=(50, 180, 50), outline=(0, 0, 0))
    draw.line([0, 0, 400, 400], fill=(0, 0, 255), width=3)

    # Rastgele LSB gürültüsü ekle (Steganaliz ve ELA testi için)
    img_np = np.array(image)
    noise = np.random.randint(0, 15, img_np.shape, dtype=np.uint8)
    noisy_img_np = np.clip(img_np + noise, 0, 255).astype(np.uint8)

    noisy_image = Image.fromarray(noisy_img_np)
    noisy_image.save(filename, quality=95)
    print(f"✅ Sentetik test görseli oluşturuldu: {filename}")
    return filename

def run_tests():
    print("=" * 60)
    print("🚀 ForensicCVEngine Otomatik Test Başlatılıyor...")
    print("=" * 60)

    # 1. Test görseli üret
    test_image_path = create_synthetic_test_image()

    # 2. ForensicCVEngine örneği oluştur ve analizi çalıştır
    engine = ForensicCVEngine(default_output_dir="outputs")
    result = engine.analyze_media(test_image_path)

    print("\n📊 Analiz Sonucu (JSON Output):")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 3. Doğrulamalar (Assertions)
    assert result["status"] == "success", "Test Başarısız: Status success değil!"
    assert os.path.exists(result["ela_image_path"]), f"Test Başarısız: ELA görseli yok -> {result['ela_image_path']}"
    assert os.path.exists(result["fft_spectrum_path"]), f"Test Başarısız: FFT spektrumu yok -> {result['fft_spectrum_path']}"
    assert os.path.exists(result["bit_planes_path"]), f"Test Başarısız: Bit Planes görseli yok -> {result['bit_planes_path']}"
    assert "entropy_score" in result, "Test Başarısız: Entropi skoru eksik!"
    assert "deepfake_probability" in result, "Test Başarısız: Deepfake olasılığı eksik!"

    print("\n" + "=" * 60)
    print("🎉 TÜM TESTLER BAŞARIYLA GEÇTİ!")
    print(f"📁 Üretilen Görseller: {result['ela_image_path']}, {result['fft_spectrum_path']}, {result['bit_planes_path']}")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
