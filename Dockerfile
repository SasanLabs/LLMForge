FROM python:3.11-slim

# Minimal system deps for building wheels if needed
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc-dev libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps early so layer caching works
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy repository into the image
COPY . /app

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

# Run the FastAPI gateway
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
