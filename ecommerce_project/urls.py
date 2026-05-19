from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import render


def handler404_view(request, exception):
    return render(request, 'store/404.html', status=404)


handler404 = handler404_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('store.urls')),
]

# En desarrollo Django sirve los archivos media directamente.
# En producción WhiteNoise sirve desde staticfiles/media (copiado en build.sh).
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
