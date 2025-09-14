#!/usr/bin/env bash

set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --noinput

# Crear carpeta media dentro de staticfiles
if [ ! -d "staticfiles/media" ]; then
    mkdir -p staticfiles/media
fi

# Si tienes archivos en la carpeta media (por ejemplo, en desarrollo)
# y quieres copiarlos a la carpeta staticfiles/media (en producción)
if [ -d "media" ]; then
    cp -r media/* staticfiles/media/
fi

python manage.py migrate --noinput
