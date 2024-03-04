from django.urls import path
from .views import RegisterEmailView
from rest_framework_simplejwt.views import (
    TokenRefreshView
)

urlpatterns = [
    path('register-email/', RegisterEmailView.as_view(), name='register-email'),
]