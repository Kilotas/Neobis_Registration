from rest_framework import serializers
from django.contrib import auth
from .models import User, Hash
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.password_validation import validate_password

class RegisterEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email']

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['token']



class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    password_confirm = serializers.CharField(max_length=15, min_length=8, write_only=True)

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        return User.objects.create_user(**validated_data)

class RegisterPersonalInfoSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=255)
    email = serializers.EmailField()

    def update(self, instance, validated_data):
        try:
            instance.first_name = validated_data.get('first_name', instance.first_name)
            instance.email = validated_data.get('email', instance.email)
            instance.save()
        except AttributeError:
            pass
        return instance




