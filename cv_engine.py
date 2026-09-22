import os
import time
from core.ela import generate_ela
from core.fft_analysis import analyze_fft
from core.steganalysis import extract_bit_planes, calculate_shannon_entropy
from core.deepfake import analyze_deepfake

class ForensicCVEngine:
    """
    Forensic Vision - Ana Görüntü İşleme & AI Orkestratör Sınıfı.
    Tüm ELA, FFT, Steganaliz ve Deepfake analizlerini tek noktadan yönetir.
    """

    def __init__(self, default_output_dir: str = "outputs"):
        self.default_output_dir = default_output_dir

    def analyze_media(self, media_path: str, output_dir: str = None) -> dict:
        """
        Verilen görsel veya medya dosyası üzerinde tüm adli bilişim & AI analizlerini gerçekleştirir.

        :param media_path: Analiz edilecek medyanın dosya yolu.
        :param output_dir: Çıktı görsellerinin kaydedileceği dizin (Varsayılan: outputs).
        :return: İstenen JSON formatındaki sonuç sözlüğü.
        """
        if not os.path.exists(media_path):
            return {
                "status": "error",
                "message": f"Dosya bulunamadı: {media_path}"
            }

        target_dir = output_dir or self.default_output_dir
        os.makedirs(target_dir, exist_ok=True)

        base_name = os.path.splitext(os.path.basename(media_path))[0]
        timestamp = int(time.time())

        # Çıktı Görsel Yolları
        ela_output = os.path.join(target_dir, f"{base_name}_ela_{timestamp}.png")
        fft_output = os.path.join(target_dir, f"{base_name}_fft_{timestamp}.png")
        bitplanes_output = os.path.join(target_dir, f"{base_name}_bitplanes_{timestamp}.png")

        try:
            # 1. ELA (Error Level Analysis)
            _, ela_path, ela_score = generate_ela(media_path, ela_output, quality=90)

            # 2. FFT (Fast Fourier Transform) Analizi
            fft_res = analyze_fft(media_path, fft_output)

            # 3. Steganaliz: Bit Planes & Shannon Entropi
            bitplanes_path = extract_bit_planes(media_path, bitplanes_output)
            entropy_score = calculate_shannon_entropy(media_path)
            is_stego_suspect = bool(entropy_score > 7.9 or fft_res.get("is_synthetic_suspect"))

            # 4. Deepfake Analizi
            deepfake_res = analyze_deepfake(media_path)
            deepfake_prob = deepfake_res.get("deepfake_probability", 0.0)

            # İstenen Standart JSON Formatında Çıktı Üret
            return {
                "status": "success",
                "ela_image_path": str(ela_path),
                "fft_spectrum_path": str(fft_res["fft_spectrum_path"]),
                "bit_planes_path": str(bitplanes_path),
                "entropy_score": float(round(entropy_score, 2)),
                "is_stego_suspect": bool(is_stego_suspect),
                "deepfake_probability": float(round(deepfake_prob, 2)),
                "details": {
                    "ela_mean_score": float(ela_score),
                    "high_freq_noise_ratio": float(fft_res.get("high_freq_noise_ratio", 0.0)),
                    "faces_detected": int(deepfake_res.get("faces_detected", 0)),
                    "deepfake_analysis_method": str(deepfake_res.get("method", ""))
                }
            }


        except Exception as e:
            return {
                "status": "error",
                "message": f"Analiz sırasında hata oluştu: {str(e)}"
            }

if __name__ == "__main__":
    print("ForensicCVEngine modülü hazır. Test için test_cv.py betiğini çalıştırın.")
