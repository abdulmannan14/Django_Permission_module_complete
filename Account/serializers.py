import self as self
from rest_framework.serializers import ModelSerializer
from Account import models as account_models
from rest_framework import serializers
from django.contrib.auth.models import User


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.CharField(required=True)

    def validate_email(self, value):
        lower_email = value.lower()
        if User.objects.filter(email__iexact=lower_email).exists():
            raise serializers.ValidationError("Email already registered to other account! ")
        return lower_email

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "password",
        ]


class LoginSerializer(ModelSerializer):
    password = serializers.CharField(required=True)
    username = serializers.CharField(required=True)

    class Meta:
        model = account_models.User
        fields = (
            'username',
            'password',
        )


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        lower_email = value.lower()
        if User.objects.filter(email__iexact=lower_email).exists():
            raise serializers.ValidationError("Email already registered to other account! ")
        return lower_email

    class Meta:
        model = account_models.User
        fields = (
            'first_name',
            'last_name',
            'username',
            'email',
            'password'
        )


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = account_models.UserProfile
        fields = '__all__'


class SendVerificationCode(serializers.Serializer):
    email = serializers.EmailField(required=True)


class EmailVerify(serializers.Serializer):
    code = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)


class PasswordCreationSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=20, required=True)
    new_password = serializers.CharField(max_length=20, required=True)


class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=20, required=True)
    email = serializers.EmailField(required=True)
    code = serializers.IntegerField(required=True)
