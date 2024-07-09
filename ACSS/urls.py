from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    #path('accounts/', include('django.contrib.auth.urls')),  # Include Django's auth URLs
    path('', include('myapp.urls')),  # Include app-level URLs
]
