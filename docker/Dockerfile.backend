# Dockerfile for Backend Service (Python FastAPI + Androguard + YARA + WeasyPrint)
FROM python:3.11-slim

# Install system libraries required by WeasyPrint (Pango, Cairo, GdkPixbuf) and YARA
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

# Copy requirements and install dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend application source code
COPY backend/ ./backend/
COPY yara_rules/ ./yara_rules/

# Expose FastAPI application port
EXPOSE 8000

# Set PYTHONPATH so backend package imports resolve cleanly
ENV PYTHONPATH=/app

# Launch Uvicorn server
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
