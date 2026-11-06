FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install system dependencies (build-essential, curl, libmagic)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Ensure ML model is trained/ready
RUN python -m app.ml.train

EXPOSE 8000

CMD ["sh", "-c", "python -m app.db_init && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

