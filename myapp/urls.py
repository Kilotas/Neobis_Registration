from django.urls import path
from .views import RegisterEmailView, VerifyEmail, RegisterPersonalInfoView, LoginAPIView, \
    RequestPasswordResetEmailView, PasswordResetConfirmView, SetNewPasswordAPIView
from rest_framework_simplejwt.views import (
    TokenRefreshView
)
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

schema_view = get_schema_view(
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('register/email/', RegisterEmailView.as_view(), name='email-verification'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify'),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('register/personal-info/', RegisterPersonalInfoView.as_view(), name='register-personal-info'),
    path('request-reset-email/', RequestPasswordResetEmailView.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

