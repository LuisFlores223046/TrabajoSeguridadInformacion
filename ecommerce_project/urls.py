"""
The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))

URL configuration for ecommerce_project project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
import os

urlpatterns = [
    path('admin/', admin.site.urls),  # Admin de Django
    path('', include('store.urls')),  # Incluye todas las URLs de la app store
]

# Configuración para servir archivos media tanto en desarrollo como en producción
if settings.DEBUG:
    # En desarrollo, Django puede servir archivos media directamente
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    # En producción, necesitamos configurar manualmente la URL para archivos media
    # Esta configuración trabajará con la estructura de carpetas propuesta 
    # (media dentro de staticfiles)
    urlpatterns += [
        path('media/<path:path>', serve, {
            'document_root': os.path.join(settings.BASE_DIR, 'media'),
        }),
    ]
