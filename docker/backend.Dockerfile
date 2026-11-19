FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    libxml2-dev \
    libxslt1-dev \
    libcairo2 \
    libglib2.0-0 \
    libgobject-2.0-0 \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

COPY backend/ ./backend/
COPY yara_rules/ ./yara_rules/

EXPOSE 8000
ENV PYTHONPATH=/app

RUN useradd -m app && mkdir -p backend/uploads backend/results && chown -R app:app /app
USER app

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
