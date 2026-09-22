FROM python:3.11-slim

# Sistem kütüphanelerini kur (OpenCV ve fontlar için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bağımlılıkları kur
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama kodlarını kopyala
COPY . .

# Dizinleri oluştur
RUN mkdir -p uploads outputs reports_generated

EXPOSE 8000 8501

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
