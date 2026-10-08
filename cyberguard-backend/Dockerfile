FROM python:3.12-slim

WORKDIR /app
COPY requirements-models.lock ./
RUN apt-get update \
	&& apt-get install --no-install-recommends -y ca-certificates curl gnupg tesseract-ocr \
	&& install -d /usr/share/postgresql-common/pgdg \
	&& curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg \
	&& . /etc/os-release && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
	&& apt-get update \
	&& apt-get install --no-install-recommends -y postgresql-client-16 \
	&& rm -rf /var/lib/apt/lists/* \
	&& pip install --no-cache-dir --require-hashes -r requirements-models.lock
COPY . .
ENV PYTHONUNBUFFERED=1
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
