#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

echo "======================================"
echo "Installing dependencies..."
echo "======================================"
pip install -r requirements.txt

echo "======================================"
echo "Running database migrations..."
echo "======================================"
python manage.py migrate --noinput

echo "======================================"
echo "Collecting static files..."
echo "======================================"
python manage.py collectstatic --noinput

echo "======================================"
echo "Verifying static files..."
echo "======================================"
ls -la staticfiles || true

echo "======================================"
echo "Build completed successfully."
echo "======================================"