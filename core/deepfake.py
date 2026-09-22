import os
import cv2
import numpy as np
from PIL import Image

def detect_faces(image_np: np.ndarray) -> list[dict]:
    """
    OpenCV Haar Cascade veya YCrCb Cilt Rengi / Kontur analizi ile yüz tespiti yapar.
    Sistemde CascadeClassifier bulunmaması durumunda güvenli fallback sağlar.

    :param image_np: BGR veya Gri numpy dizisi görsel.
    :return: Tespit edilen yüzlerin koordinat listesi [{'x': x, 'y': y, 'w': w, 'h': h}]
    """
    face_boxes = []

    # 1. Öncelik: OpenCV CascadeClassifier (eğer mevcutsa)
    if hasattr(cv2, 'CascadeClassifier'):
        try:
            if len(image_np.shape) == 3:
                gray = cv2.cvtColor(image_np, cv2.COLOR_BGR2GRAY)
            else:
                gray = image_np

            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml' if hasattr(cv2, 'data') else ''
            if os.path.exists(cascade_path):
                face_cascade = cv2.CascadeClassifier(cascade_path)
                faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
                for (x, y, w, h) in faces:
                    face_boxes.append({"x": int(x), "y": int(y), "w": int(w), "h": int(h)})
                if face_boxes:
                    return face_boxes
        except Exception:
            pass

    # 2. Fallback: YCrCb Renk Alanı & Kontur Bazlı Yüz / Aday Bölge Tespiti
    try:
        if len(image_np.shape) == 3:
            ycrcb = cv2.cvtColor(image_np, cv2.COLOR_BGR2YCrCb)
            # Cilt rengi aralığı (YCrCb)
            lower_skin = np.array([0, 133, 77], dtype=np.uint8)
            upper_skin = np.array([255, 173, 127], dtype=np.uint8)
            mask = cv2.inRange(ycrcb, lower_skin, upper_skin)

            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            h_img, w_img = image_np.shape[:2]
            min_area = (h_img * w_img) * 0.02

            for cnt in contours:
                area = cv2.contourArea(cnt)
                if area > min_area:
                    x, y, w, h = cv2.boundingRect(cnt)
                    aspect_ratio = float(w) / h
                    if 0.5 <= aspect_ratio <= 1.8:
                        face_boxes.append({"x": int(x), "y": int(y), "w": int(w), "h": int(h)})
    except Exception:
        pass

    return face_boxes


def analyze_deepfake(image_path: str) -> dict:
    """
    Görsel üzerindeki yüzleri ve doku tutarsızlıklarını analiz ederek
    Deepfake / Yüz Manipülasyonu olasılık skoru (0.0 - 1.0) üretir.

    :param image_path: Girdi görselinin dosya yolu.
    :return: Deepfake analiz sonuç sözlüğü.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Girdi görseli bulunamadı: {image_path}")

    img = cv2.imread(image_path)
    if img is None:
        pil_img = Image.open(image_path).convert("RGB")
        img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    face_boxes = detect_faces(img)
    faces_count = len(face_boxes)

    if faces_count == 0:
        # Yüz bulunamadıysa genel görsel doku bulanıklık & Laplacian varyansı analizi
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        
        # Çok düz veya aşırı pürüzsüz yapay görsellerde bulanıklık yüksek varyans düşük çıkabilir
        prob = 0.15 if laplacian_var > 100 else 0.45
        return {
            "faces_detected": 0,
            "deepfake_probability": round(prob, 2),
            "method": "Global Texture Analysis (No Face Detected)",
            "face_locations": []
        }

    # Yüzler üzerinde dokusal tutarsızlık ve renk gradyanı analizi
    total_face_score = 0.0
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    for face in face_boxes:
        x, y, w, h = face["x"], face["y"], face["w"], face["h"]
        face_crop = gray[y:y+h, x:x+w]

        if face_crop.size == 0:
            continue

        # Yüz kenar keskinliği (Laplacian Variance)
        lap_var = cv2.Laplacian(face_crop, cv2.CV_64F).var()

        # Renk kanalları arasındaki standart sapma farkı (Color Bleeding / Boundary Artifacts)
        face_color_crop = img[y:y+h, x:x+w]
        b, g, r = cv2.split(face_color_crop)
        std_diff = abs(np.std(r) - np.std(b))

        # Heuristic Deepfake skoru hesabı:
        # Yapay derin sahte yüzlerde yumuşatılmış cilt alanları (düşük lap_var) ve
        # kenarlarda renk uyumsuzluğu (yüksek std_diff) gözlenir.
        face_score = 0.2
        if lap_var < 80.0:
            face_score += 0.35
        if std_diff > 15.0:
            face_score += 0.35

        total_face_score += min(face_score, 0.95)

    avg_probability = float(total_face_score / faces_count)

    return {
        "faces_detected": faces_count,
        "deepfake_probability": round(avg_probability, 2),
        "method": "Haar Facial Crop + Texture Artifact Heuristics",
        "face_locations": face_boxes
    }
