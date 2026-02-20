#!/bin/sh

echo "Waiting for database..."

for i in $(seq 1 30); do
  nc -z db 5432 && break
  echo "Waiting... ($i)"
  sleep 1
done

if ! nc -z db 5432; then
  echo "Database not reachable"
  exit 1
fi

echo "Running migrations..."
python -m flask db upgrade

echo "Starting Gunicorn..."
exec gunicorn -w 4 -b 0.0.0.0:1412 run:app
