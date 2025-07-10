FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/app ./app
COPY backend/alembic.ini .
COPY backend/alembic ./alembic
COPY backend/scripts ./scripts
COPY backend/assets ./assets

# Create required directories
RUN mkdir -p uploads/agents

# Make startup script executable
RUN chmod +x ./scripts/start.sh

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=8000

# Expose the port
EXPOSE 8000

# Run the startup script
CMD ["./scripts/start.sh"] 