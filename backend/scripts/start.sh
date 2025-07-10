#!/bin/bash
set -e

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL is ready!"

# Create firebase credentials directory if it doesn't exist
mkdir -p /app/config


if [ ! -f "$FIREBASE_CREDENTIALS" ]; then
    echo "Warning: Firebase credentials file not found. Creating a placeholder..."
    cat > "$FIREBASE_CREDENTIALS" << 'EOF'
{
    "type": "service_account",
    "project_id": "demo-project",
    "private_key_id": "demo123456789",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDK/eDH0MDgBNHs\nYuXwHMnMYGz+86YJjYoXVbKdUGHQZXYVEVlc8rYA+VXbU1AqhD+c7yT9V9EaEjPO\nXGVWS6dWQh4Kh5g7y1O5SHIwQhDHK+AAqMgBfZhzEHJBtO8CXG8TDyxhfHXxjWpD\nGPz/RJ7GhW9cHYQOvP4yZAp3ZNGYQJwUlhNLGr80XEhGVlkZ5WPL0YFzwOxvqGQs\nQVVxGGj5h7YHJt1YmZwF6cBGGX8AUetJkMTgQEJSNsaK4Pl+MZUGQOhQEynK3qO2\nWf+7XZl4XPx9Qw+WPYEoHHlGgGQR4YUpL+qzVxYwNAXhVxd9k+YPp5JZHtGQAXeO\nZhxDo1QLAgMBAAECggEABBj/H/JGXuVGoCjR6J0XF+kQTOuTgZBvgapkpPTYwfXQ\nPRKzGWEpGUPVnVb3gMDqbqQe7EVJZ8Nj/zHmXf9c4qKxpXwNl7kYmPpuQOHmA8Nq\nXPE3QZH3YSRz1YXF/pA9RQqG5F4JBJjz5LcUR+ax9aSxPu26xwDHOpR4EIR9Aovx\nJfcg7MTAY4YuGBe0oLQbEWoUQqXgUIVEzWcqiDGXF0uuMZzpW6YVk5ZvWHXz7SVK\nE7e1XQN6sMTYqrmnFGkBhuvXiBkPZHsOEHBVxXVqytE8FJAqXwPwFqxWj4RhNS/w\nkMUv5ZyH6UOFuBXtSe1XGGEqktNVGPBhAkEo4BbhAQKBgQD1+fdC9zzDwA4KoNnk\nVxQbCpC7Zr5F8Mycer0SV/3Gg6okzo9vXl+vqVHXqYNGnAEFkLLhEzwpZB0cnqWk\nQswrGvZ5FvUSKd7rMfI0Uh5FxhYCuUwwZW6gVKEZDCXF6N7KBbMPaYVZuGwD7oQk\nUQKBgQDTKj+RKqFrwhZM4cVJVgqHgQmMvHXC7Hy3Sj8Yl9ZHxgsnrkoNXXXRDNwp\nEWVoTy4Xr1BXuBxFEgEBpuPGBlHVXLZRzaP1pCZVqftxiHDqGlAh4y3yZtKHSTGj\n1B6OZlYXxvD+9K5Ki1ZwM3JxpY4YE5zASL7cUrV+gUUE2VoengKBgQDxIrXXFR8l\nAgMBAAECggEABBj/H/JGXuVGoCjR6J0XF+kQTOuTgZBvgapkpPTYwfXQ\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-demo@demo-project.iam.gserviceaccount.com",
    "client_id": "123456789",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-demo%40demo-project.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}
EOF
    echo "Created placeholder Firebase credentials at $FIREBASE_CREDS_PATH"
fi

# Run migrations
echo "Running database migrations..."
alembic upgrade head

# Calculate number of workers based on CPU cores
WORKERS=$((2 * $(nproc) + 1))

# Start the application with Gunicorn
echo "Starting FastAPI application with Gunicorn..."
gunicorn app.main:app \
    --workers $WORKERS \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --timeout 120 \
    --keep-alive 5 \
    --log-level info \
    --access-logfile - \
    --error-logfile - \
    --preload 