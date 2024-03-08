import os
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegistrationSerializer, EmailVerificationSerializer,RegisterPersonalInfoSerializer, LoginSerializer
from django.http import HttpResponseRedirect
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.conf import settings
from django.contrib.auth.models import User
from django.shortcuts import redirect
from rest_framework.permissions import AllowAny
import jwt
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed


class CustomRedirect(HttpResponseRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

class RegisterEmailView(APIView):
    permission_classes = [AllowAny]
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data) # создание экземляра класса сериализатора
        serializer.is_valid(raise_exception=True)
        user = serializer.save() #

        token = RefreshToken.for_user(user) # создание нового токена доступа для конкретного пользователя
        token_payload = {'email': user.email} # создает словарь, который будет содержать информацию , которая будет добавлена к токену
        token['email'] = user.email  # значение адрес электронной почты
        token['payload'] = token_payload # значение дополнительных данных
        token = str(token.access_token) # преобразует объект токена в строку

        current_site = get_current_site(request).domain  # получение домена нашего сайта, на котором работает приложение
        relative_link = reverse('email-verify') # позволяет получить url адрес
        absurl = 'http://' + current_site + relative_link + "?token=" + token
        email_body = 'Hi ' + ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}

        try:
            Util.send_email(data)
        except Exception as e:
            print(f"Failed to send verification email to {user.email}: {e}")
            return Response({'message': 'Failed to send verification email.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        token_payload = {'email': user.email}

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class VerifyEmail(APIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        User = get_user_model()  # Получение модели пользователя

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            email = payload['email']
            user = User.objects.get(id=user_id, email=email)
            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return redirect(reverse('register-personal-info') + f'?email={email}')
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation link has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except (jwt.exceptions.DecodeError, User.DoesNotExist):
            return Response({'error': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)


class RegisterPersonalInfoView(APIView):
    serializer_class = RegisterPersonalInfoSerializer
    permission_classes = [AllowAny,]

    def put(self, request):
        User = get_user_model()
        user_email = request.GET.get('email')
        user_email = user_email.rstrip('/')
        email_field = request.data.get('email')

        if not user_email or not email_field or user_email != email_field:
            return Response({'error': 'Email mismatch'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # получаем пользователя через миейл
            user = User.objects.get(email=email_field)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_NOT_FOUND)

        serializer = RegisterPersonalInfoSerializer(user, data=request.data) # используетася для обновления объектов в сериализаторе
        if serializer.is_valid():
            serializer.save()

            return Response(data={"email": user_email}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny,]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


