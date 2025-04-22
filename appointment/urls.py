from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('appointments.urls')),  # Includes app-level URLs
    path('', include('chat.urls')),
]





