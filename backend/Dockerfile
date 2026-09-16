# Small official Python image
FROM python:3.12-slim

# Print logs immediately and don't write .pyc files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first so Docker can reuse this layer when only code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as a normal user, not root (basic container security)
RUN useradd --create-home appuser
USER appuser

# Render sets PORT automatically. Hugging Face Spaces needs PORT=7860.
# Locally it falls back to 8000.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
