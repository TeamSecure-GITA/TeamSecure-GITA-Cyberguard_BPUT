FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN apt-get update \
	&& apt-get install --no-install-recommends -y tesseract-ocr \
	&& rm -rf /var/lib/apt/lists/* \
	&& pip install --no-cache-dir -r requirements.txt -r requirements-models.txt
COPY . .
ENV PYTHONUNBUFFERED=1
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
