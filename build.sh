#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --noinput

# Copiar imágenes de productos al directorio de estáticos para que WhiteNoise las sirva
if [ -d "media" ] && [ "$(ls -A media 2>/dev/null)" ]; then
    mkdir -p staticfiles/media
    cp -r media/. staticfiles/media/
fi

python manage.py migrate --noinput
