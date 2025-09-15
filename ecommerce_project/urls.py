# En ecommerce_project/urls.py

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
import os

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('store.urls')),
]

# Configuración para servir archivos media
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    urlpatterns += [
        path('media/<path:path>', serve, {
            'document_root': os.path.join(settings.BASE_DIR, 'media'),
        }),
    ]

# ✅ AÑADIR: Handler personalizado para 404
def custom_404_view(request, exception):
    """Vista personalizada para errores 404"""
    from django.shortcuts import render
    return render(request, '404.html', status=404)

# ✅ REGISTRAR el handler
handler404 = custom_404_view