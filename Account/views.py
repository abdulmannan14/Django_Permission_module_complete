from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework.response import Response
from Account import models as account_models, utils as account_utils, serializers as account_user_auth_serializers
from permission_module import utils as backend_utils
from rest_framework.authtoken.models import Token


class RegisterApi(APIView):
    serializer_class = account_user_auth_serializers.RegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        account = serializer.save()
        account.username = request.data.get('email')
        account.is_active = True
        account.set_password(request.data.get('password'))
        account.save()
        user_profile = account_models.UserProfile.objects.create(user=account,
                                                                 verification_code=account_utils.random_digits())
        user_profile.save()

        token = Token.objects.get_or_create(user=account)[0].key
        get_user = get_object_or_404(User, email=account.username)
        context = {'first_name': get_user.first_name, 'code': user_profile.verification_code,
                   'username': get_user.username,
                   'message': 'enter the code in your app in order to'
                              ' verify your email.'
                   }
        account_utils.thread_making(backend_utils.send_email, ["Permission Password Reset", context, get_user])
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
                                           msg='User Registered Successfully'))


class EmailVerify(APIView):
    permission_classes = (AllowAny,)
    serializer_class = account_user_auth_serializers.EmailVerify

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        requested_data = request.data
        code = requested_data.get('code')
        username = requested_data.get('email')
        user_profile = account_utils.get_user_profile(username, code)
        if user_profile:
            if not user_profile.email_verified:
                user_profile.email_verified = True
                user_profile.verification_code = account_utils.random_digits()  # to change code immediately to avoid future attacks
                user_profile.save()
                return Response(backend_utils.success_response(msg="email verified successfully"))
            else:
                return Response(backend_utils.success_response(msg="Email Already Verified"))
        else:
            return Response(backend_utils.failure_response(msg="incorrect verification code"))


class LoginApi(APIView):
    permission_classes = (AllowAny,)
    serializer_class = account_user_auth_serializers.LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.on_valid_request_data(serializer.validated_data, request)

    def on_valid_request_data(self, data, request):
        username = data.get('username')
        password = data.get('password')
        print("email====", username)
        print("password====", password)
        user = authenticate(username=username, password=password)
        print("user=====", user)
        if user is not None:
            user_profile = account_models.UserProfile.objects.get_or_create(user=user)[0]
            print("Profile====", user_profile)
            if user_profile.email_verified:
                user_profile_serializer = account_user_auth_serializers.UserProfileSerializer(user_profile)
                user_profile_serializer = user_profile_serializer.data
                token, created = Token.objects.get_or_create(user=user)
                # login(request, user)
                response = {
                    'token': token.key,
                    'user_profile': user_profile_serializer,
                    'permissions': account_utils.get_all_permissions(user)
                }
                return Response(
                    backend_utils.success_response(status_code=status.HTTP_200_OK, data=response,
                                                   msg='User Login Successfully'))
            return Response(
                backend_utils.success_response(status_code=status.HTTP_400_BAD_REQUEST, data=None,
                                               msg='Email is not verified, Please verify your email'))
        return Response(backend_utils.failure_response(msg="User not found!"), status=403)


class LogoutApi(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # logout(request)
        request.user.auth_token.delete()
        response = {
        }
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=response,
                                           msg='User Logged out Successfully'))


class SendVerificationCode(APIView):
    permission_classes = (AllowAny,)
    serializer_class = account_user_auth_serializers.SendVerificationCode

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        requested_data = request.data
        email = requested_data.get('email')
        try:
            get_user = get_object_or_404(User, email=email)
            get_userprofile = get_user.userprofile
            context = {'first_name': get_user.first_name, 'code': get_userprofile.verification_code,
                       'username': get_user.username,
                       'message': 'enter the code in your app in order to'
                                  ' verify your email.'
                       }
            account_utils.thread_making(backend_utils.send_email, ["Permission Password Reset", context, get_user])
            return Response(backend_utils.success_response(msg='Verification code has been sent successfully'))
        except Exception as e:
            return Response(backend_utils.failure_response(msg='Email Not Found'))


class ForgetPasswordVerifyCodeApi(APIView):
    permission_classes = (AllowAny,)
    serializer_class = account_user_auth_serializers.EmailVerify

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        requested_data = request.data
        code = requested_data.get('code')
        username = requested_data.get('email')
        user_profile = account_utils.get_user_profile(username, code)
        if user_profile:
            return Response(backend_utils.success_response(msg="email verified successfully"))

        else:
            return Response(backend_utils.failure_response(msg="incorrect verification code"))


class SetNewPasswordApi(APIView):
    permission_classes = (AllowAny,)
    serializer_class = account_user_auth_serializers.SetNewPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = request.data.get('new_password')
        email = request.data.get('email')
        code = request.data.get('code')
        try:
            user_profile = account_utils.get_user_profile(email, code)
            print("this is ")
            user_profile.user.set_password(password)
            user_profile.user.save()
            user_profile.verification_code = account_utils.random_digits()
            user_profile.save()
            message = "Password Reset Successfully!"
            return Response(backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
                                                           msg=message))
        except Exception as e:
            return Response(backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                                           msg='Something went wrong'))


class ChangePassword(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = account_user_auth_serializers.PasswordCreationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        get_username = request.user.username
        user_profile = account_utils.get_user_profile(username=get_username)
        requested_data = request.data
        current_password = requested_data.get('current_password')
        new_password = requested_data.get('new_password')
        if user_profile:
            if user_profile.user.check_password(current_password):
                if current_password != new_password:
                    user_profile.user.set_password(new_password)
                    user_profile.user.save()
                    return Response(backend_utils.success_response(msg="password changed Successfully"))
                return Response(backend_utils.failure_response(msg="new and current password cannot be same"))
            return Response(backend_utils.failure_response(msg="current password does not matched"))
        return Response(backend_utils.failure_response(msg="no user with this verification code found"))
