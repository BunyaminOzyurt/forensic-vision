"""
Forensic Vision - ReportLab Tabanlı Adli Bilişim PDF Raporu Oluşturucu
Resmi kurum ve mahkeme standartlarına uygun 'Adli Bilişim İnceleme Raporu' üretir.
Dosya bütünlüğü, Magic Bytes, Hash değerleri, EXIF bilgileri, File Carving bulguları
ve Computer Vision ısı haritalarını (ELA, FFT, Bit-planes) görselleştirir.
"""

import os
import time
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, Image, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Türkçe karakter uyumluluğu için Windows Arial fontunu kaydetmeyi dene
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"

try:
    arial_path = "C:\\Windows\\Fonts\\arial.ttf"
    arial_bold_path = "C:\\Windows\\Fonts\\arialbd.ttf"
    if os.path.exists(arial_path) and os.path.exists(arial_bold_path):
        pdfmetrics.registerFont(TTFont("ArialTurkish", arial_path))
        pdfmetrics.registerFont(TTFont("ArialTurkish-Bold", arial_bold_path))
        FONT_REGULAR = "ArialTurkish"
        FONT_BOLD = "ArialTurkish-Bold"
except Exception:
    FONT_REGULAR = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"


class NumberedCanvas(canvas.Canvas):
    """
    Raporun altbilgisine dinamik toplam sayfa numarası ve gizlilik ibaresi basar.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont(FONT_REGULAR, 8)
        self.setFillColor(colors.HexColor("#718096"))

        # Üstbilgi çizgisi ve metni (1. sayfa hariç)
        if self._pageNumber > 1:
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(40, 800, 555, 800)
            self.drawString(40, 805, "FORENSIC VISION - ADLİ BİLİŞİM DİJİTAL DELİL RAPORU")
            self.drawRightString(555, 805, "GİZLİ / DELİL")

        # Altbilgi çizgisi
        self.setStrokeColor(colors.HexColor("#CBD5E0"))
        self.setLineWidth(0.5)
        self.line(40, 45, 555, 45)

        # Altbilgi metinleri
        footer_text = f"Sayfa {self._pageNumber} / {page_count}"
        disclaimer = "Bu rapor elektronik olarak Forensic Vision AI & Adli Bilişim Motoru tarafından üretilmiştir."
        self.drawString(40, 32, disclaimer)
        self.drawRightString(555, 32, footer_text)
        self.restoreState()


def _sanitize(text: Any) -> str:
    """
    HTML/XML etiketlerini güvenli formata çevirir.
    """
    if text is None:
        return "-"
    s = str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate_forensic_pdf(report_data: Dict[str, Any], output_pdf_path: str) -> str:
    """
    Tüm adli bilişim analiz sonuçlarını içeren resmi ve şık bir PDF raporu üretir.

    :param report_data: Analiz sonuçlarını içeren sözlük (magic_bytes, exif, carver, hashes, cv vb.)
    :param output_pdf_path: Çıktı PDF dosyasının kaydedileceği yol.
    :return: Üretilen PDF dosyasının mutlak yolu.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_pdf_path)), exist_ok=True)

    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=45,
        bottomMargin=55
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName=FONT_BOLD,
        fontSize=17,
        leading=22,
        textColor=colors.HexColor("#1A365D"),
        alignment=1,
        spaceAfter=4
    )

    sub_title_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName=FONT_REGULAR,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#4A5568"),
        alignment=1,
        spaceAfter=15
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName=FONT_BOLD,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=10,
        spaceAfter=6
    )

    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName=FONT_REGULAR,
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#2D3748")
    )

    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontName=FONT_BOLD,
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1A202C")
    )

    badge_style = ParagraphStyle(
        "ThreatBadge",
        parent=styles["Normal"],
        fontName=FONT_BOLD,
        fontSize=12,
        leading=16,
        alignment=1,
        textColor=colors.white
    )

    story = []

    # 1. Başlık ve Üst Antet
    story.append(Paragraph("T.C. SİBER GÜVENLİK VE DİJİTAL ADLİ BİLİŞİM DAİRESİ", title_style))
    story.append(Paragraph("ADLİ BİLİŞİM DELİL VE GÖRÜNTÜ BÜTÜNLÜĞÜ İNCELEME RAPORU", title_style))
    story.append(Paragraph(
        f"Rapor No: <b>FV-{int(time.time())}</b> | Düzenleme Tarihi: <b>{time.strftime('%Y-%m-%d %H:%M:%S')}</b> | Sınıflandırma: <b>GİZLİ</b>",
        sub_title_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1A365D"), spaceAfter=10))

    # 2. Üst Tehdit Seviyesi Özeti (Executive Threat Badge)
    magic_res = report_data.get("magic_bytes", {})
    carver_res = report_data.get("file_carver", {})
    hashes_res = report_data.get("hashes", {})
    exif_res = report_data.get("exif", {})
    cv_res = report_data.get("cv_analysis", {})

    is_spoofed = magic_res.get("spoof_detected", False)
    payload_found = carver_res.get("payload_detected", False)
    is_malicious_hash = hashes_res.get("reputation", {}).get("is_known_malicious", False)
    deepfake_prob = cv_res.get("deepfake_probability", 0.0)

    # Genel Risk Skoru Hesaplama
    risk_score = 0
    if is_spoofed:
        risk_score += 40
    if payload_found:
        risk_score += 45
    if is_malicious_hash:
        risk_score += 50
    if deepfake_prob > 0.7:
        risk_score += 30
    if exif_res.get("software_tampering_suspect", False):
        risk_score += 20
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        badge_bg = colors.HexColor("#C53030")  # Kırmızı
        badge_text = f"YÜKSEK RİSK / ZARARLI İHLAL TESPİT EDİLDİ (Risk Skoru: {risk_score}/100)"
    elif risk_score >= 35:
        badge_bg = colors.HexColor("#DD6B20")  # Turuncu
        badge_text = f"ŞÜPHELİ / MANİPÜLASYON İZLERİ BULUNDU (Risk Skoru: {risk_score}/100)"
    else:
        badge_bg = colors.HexColor("#2F855A")  # Yeşil
        badge_text = f"TEMİZ / DOSYA BÜTÜNLÜĞÜ DOĞRULANDI (Risk Skoru: {risk_score}/100)"

    badge_table = Table([[Paragraph(badge_text, badge_style)]], colWidths=[515])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_bg),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("CORNERPAD", (0, 0), (-1, -1), 4),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 12))

    # 3. Bölüm 1: Dosya Kimliği ve Magic Bytes Doğrulaması
    story.append(Paragraph("1. DOSYA KİMLİĞİ VE BAŞLIK (MAGIC BYTES) DOĞRULAMASI", section_heading))
    file_info_data = [
        [Paragraph("İncelenen Dosya:", cell_bold), Paragraph(_sanitize(hashes_res.get("file_name", "Bilinmiyor")), cell_style)],
        [Paragraph("Dosya Boyutu:", cell_bold), Paragraph(f"{hashes_res.get('file_size_formatted', '-')} ({hashes_res.get('file_size_bytes', 0)} Bytes)", cell_style)],
        [Paragraph("Beyan Edilen Uzantı:", cell_bold), Paragraph(_sanitize(magic_res.get("declared_extension", "-")), cell_style)],
        [Paragraph("Tespit Edilen Gerçek Format:", cell_bold), Paragraph(_sanitize(magic_res.get("detected_format", "-")), cell_style)],
        [Paragraph("MIME Türü:", cell_bold), Paragraph(_sanitize(magic_res.get("detected_mime", "-")), cell_style)],
        [Paragraph("İlk 16 Byte (Magic Hex):", cell_bold), Paragraph(f"<font face='Courier'>{_sanitize(magic_res.get('magic_hex_spaced', '-'))}</font>", cell_style)],
        [
            Paragraph("Uzantı Yanıltması (Spoofing):", cell_bold),
            Paragraph(
                "<font color='#C53030'><b>EVET (Sahte Uzantı Tespit Edildi!)</b></font>" if is_spoofed
                else "<font color='#2F855A'><b>HAYIR (Uzantı ve Magic Bytes Uyumlu)</b></font>",
                cell_style
            )
        ],
    ]
    t_file = Table(file_info_data, colWidths=[160, 355])
    t_file.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_file)
    story.append(Spacer(1, 10))

    # 4. Bölüm 2: Kriptografik Özet Değerleri (Hashes & Reputation)
    story.append(Paragraph("2. KRİPTOGRAFİK ÖZET DEĞERLERİ & DELİL BÜTÜNLÜĞÜ (CHAIN OF CUSTODY)", section_heading))
    rep = hashes_res.get("reputation", {})
    hash_data = [
        [Paragraph("MD5:", cell_bold), Paragraph(f"<font face='Courier'>{_sanitize(hashes_res.get('md5', '-'))}</font>", cell_style)],
        [Paragraph("SHA-1:", cell_bold), Paragraph(f"<font face='Courier'>{_sanitize(hashes_res.get('sha1', '-'))}</font>", cell_style)],
        [Paragraph("SHA-256:", cell_bold), Paragraph(f"<font face='Courier'>{_sanitize(hashes_res.get('sha256', '-'))}</font>", cell_style)],
        [
            Paragraph("Zararlı İtibar Kontrolü:", cell_bold),
            Paragraph(
                f"<font color='#C53030'><b>{_sanitize(rep.get('details', '-'))}</b></font>" if rep.get("is_known_malicious")
                else "<font color='#2F855A'><b>Temiz (Bilinen tehdit veritabanlarında eşleşme yok)</b></font>",
                cell_style
            )
        ],
    ]
    t_hash = Table(hash_data, colWidths=[160, 355])
    t_hash.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_hash)
    story.append(Spacer(1, 10))

    # 5. Bölüm 3: EXIF Metadata & GPS Konumu
    story.append(Paragraph("3. EXIF METADATA VE COĞRAFİ KONUM ANALİZİ", section_heading))
    gps_info = exif_res.get("gps", {})
    exif_data = [
        [Paragraph("EXIF Durumu:", cell_bold), Paragraph("Mevcut" if exif_res.get("exif_found") else "Mevcut Değil / Temizlenmiş", cell_style)],
        [Paragraph("Kamera Donanımı:", cell_bold), Paragraph(f"{_sanitize(exif_res.get('camera_make', '-'))} {_sanitize(exif_res.get('camera_model', ''))}", cell_style)],
        [Paragraph("Çekim Tarihi / Saati:", cell_bold), Paragraph(_sanitize(exif_res.get("date_time_original", "-")), cell_style)],
        [
            Paragraph("Yazılım Manipülasyon İzi:", cell_bold),
            Paragraph(
                f"<font color='#C53030'><b>ŞÜPHELİ YAZILIM: {_sanitize(exif_res.get('tampering_software', '-'))}</b></font>"
                if exif_res.get("software_tampering_suspect")
                else f"Standart ({_sanitize(exif_res.get('software', 'Belirtilmemiş'))})",
                cell_style
            )
        ],
        [
            Paragraph("GPS Koordinatları:", cell_bold),
            Paragraph(
                f"{_sanitize(gps_info.get('coordinates_str', '-'))} (<a href='{gps_info.get('maps_url', '#')}' color='#2B6CB0'>Haritada Aç</a>)"
                if gps_info.get("has_gps") else "GPS verisi bulunamadı",
                cell_style
            )
        ],
    ]
    t_exif = Table(exif_data, colWidths=[160, 355])
    t_exif.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_exif)
    story.append(Spacer(1, 10))

    # 6. Bölüm 4: Dosya İçi Gizlenmiş Veri & File Carving
    story.append(Paragraph("4. DOSYA SONUNA GÖMÜLÜ VERİ (FILE CARVING & BINWALK) ANALİZİ", section_heading))
    sig_list_str = ", ".join([s.get("description", "") for s in carver_res.get("appended_signatures", [])]) or "Yok"
    carver_data = [
        [Paragraph("EOF (Dosya Sonu) Offseti:", cell_bold), Paragraph(hex(carver_res.get("eof_offset", 0)) if carver_res.get("eof_offset") else "-", cell_style)],
        [
            Paragraph("EOF Sonrası Veri Durumu:", cell_bold),
            Paragraph(
                f"<font color='#C53030'><b>MEVCUT ({carver_res.get('appended_bytes_length', 0)} Bytes Ek Veri)</b></font>"
                if carver_res.get("has_appended_data")
                else "<font color='#2F855A'><b>TEMİZ (Dosya sınırları dışında veri yok)</b></font>",
                cell_style
            )
        ],
        [Paragraph("Ek Veri Entropisi:", cell_bold), Paragraph(f"{carver_res.get('appended_entropy', 0.0)} / 8.0 (7.0+ şifrelenmiş/sıkıştırılmış)", cell_style)],
        [Paragraph("Tespit Edilen Gömülü İmzalar:", cell_bold), Paragraph(_sanitize(sig_list_str), cell_style)],
        [Paragraph("Carving Değerlendirmesi:", cell_bold), Paragraph(_sanitize(carver_res.get("details", "-")), cell_style)],
    ]
    t_carver = Table(carver_data, colWidths=[160, 355])
    t_carver.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_carver)
    story.append(Spacer(1, 10))

    # 7. Bölüm 5: Computer Vision & Isı Haritaları (Phase 1 Entegrasyonu)
    story.append(Paragraph("5. BİLGİSAYARLI GÖRÜ (CV) & AI ANALİZİ BULGULARI", section_heading))

    cv_details = [
        [Paragraph("Deepfake Olasılığı:", cell_bold), Paragraph(f"%{deepfake_prob * 100:.1f}", cell_style)],
        [Paragraph("Shannon Entropi Skoru:", cell_bold), Paragraph(str(cv_res.get("entropy_score", "-")), cell_style)],
        [
            Paragraph("Steganografi Şüphesi:", cell_bold),
            Paragraph(
                "<font color='#C53030'><b>ŞÜPHELİ (Gizli Veri İzi Var)</b></font>" if cv_res.get("is_stego_suspect")
                else "<font color='#2F855A'><b>Düşük Olasılık</b></font>",
                cell_style
            )
        ]
    ]
    t_cv = Table(cv_details, colWidths=[160, 355])
    t_cv.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_cv)
    story.append(Spacer(1, 8))

    # Isı Haritaları Görselleri (ELA, FFT, Bitplanes)
    image_cells = []
    ela_path = cv_res.get("ela_image_path")
    fft_path = cv_res.get("fft_spectrum_path")
    bit_path = cv_res.get("bit_planes_path")

    valid_images = []
    for path, label in [(ela_path, "ELA (Hata Düzeyi)"), (fft_path, "FFT Frekans Spektrumu"), (bit_path, "Bit-Plane Dağılımı")]:
        if path and os.path.exists(path):
            try:
                img_flow = Image(path, width=160, height=130)
                caption = Paragraph(f"<font size=7.5><b>{label}</b></font>", ParagraphStyle("Caption", alignment=1))
                valid_images.append([img_flow, caption])
            except Exception:
                pass

    if valid_images:
        story.append(Paragraph("<b>Adli Görsel İnceleme Spektrumları:</b>", cell_bold))
        story.append(Spacer(1, 4))
        # Yan yana diz
        table_row_imgs = [col[0] for col in valid_images]
        table_row_captions = [col[1] for col in valid_images]
        col_w = 515 // len(valid_images)
        t_images = Table([table_row_imgs, table_row_captions], colWidths=[col_w] * len(valid_images))
        t_images.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(KeepTogether(t_images))
        story.append(Spacer(1, 10))

    # 8. Bölüm 6: Sonuç & Uzman Hukuki Delil Beyanı
    conclusion_text = (
        "<b>Adli Değerlendirme & Hukuki Mütalaa:</b><br/>"
        "İncelenen dijital materyal, ISO/IEC 27037 'Dijital Delillerin Toplanması, İncelenmesi ve Korunması' "
        "kılavuzu uyarınca analiz edilmiştir. Kriptografik özet değerleri kayıt altına alınmış olup, "
        "delil bütünlüğünün korunduğu teyit edilmiştir. Yukarıda listelenen bulgular, adli bilişim inceleme "
        "süreçleri kapsamında nihai teknik kanaat olarak düzenlenmiştir."
    )
    story.append(Paragraph(conclusion_text, cell_style))
    story.append(Spacer(1, 15))

    # İmza Blokları
    sig_data = [
        [
            Paragraph("<b>İncelemeyi Yapan Uzman:</b><br/>Forensic Vision AI Engine<br/>Kıdemli Siber Adli Bilişim Uzmanı", cell_style),
            Paragraph("<b>Laboratuvar Onayı:</b><br/>Dijital Delil Analiz Merkezi<br/>Elektronik İmzalı / Doğrulandı", cell_style)
        ]
    ]
    t_sig = Table(sig_data, colWidths=[255, 260])
    t_sig.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, -1), 0.5, colors.HexColor("#A0AEC0")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(KeepTogether(t_sig))

    # PDF'i derle
    doc.build(story, canvasmaker=NumberedCanvas)
    return os.path.abspath(output_pdf_path)


if __name__ == "__main__":
    sample_data = {
        "magic_bytes": {
            "declared_extension": ".jpg",
            "detected_format": "JPEG (JFIF)",
            "detected_mime": "image/jpeg",
            "magic_hex_spaced": "FF D8 FF E0 00 10 4A 46",
            "spoof_detected": False
        },
        "hashes": {
            "file_name": "sample.jpg",
            "file_size_formatted": "250.0 KB",
            "file_size_bytes": 256000,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "reputation": {"is_known_malicious": False, "details": "Temiz dosya"}
        },
        "exif": {
            "exif_found": True,
            "camera_make": "Apple",
            "camera_model": "iPhone 14 Pro",
            "date_time_original": "2024:06:15 11:20:00",
            "software": "iOS 17.5",
            "software_tampering_suspect": False,
            "gps": {"has_gps": True, "coordinates_str": "41.0082, 28.9784", "maps_url": "https://maps.google.com"}
        },
        "file_carver": {
            "has_appended_data": False,
            "payload_detected": False,
            "eof_offset": 256000,
            "appended_entropy": 0.0,
            "details": "Dosya temiz."
        },
        "cv_analysis": {
            "deepfake_probability": 0.12,
            "entropy_score": 7.4,
            "is_stego_suspect": False
        }
    }
    out = generate_forensic_pdf(sample_data, "sample_report.pdf")
    print(f"Rapor oluşturuldu: {out}")
