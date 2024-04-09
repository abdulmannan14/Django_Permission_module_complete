from django.urls import path, reverse
# from Account.views_api import *
from Account import views as account_views

urlpatterns = [
    path('registerz/', account_views.RegisterApi.as_view(), name='registerr'),
    path('emailverify/', account_views.EmailVerify.as_view(), name='email-verify'),
    path('login/', account_views.LoginApi.as_view(), name='login'),
    path('logout/', account_views.LogoutApi.as_view(), name='logout'),
    path('sendverificationcode/', account_views.SendVerificationCode.as_view(), name='send-verification-code'),
    path('forgetpasswordverifycode/', account_views.ForgetPasswordVerifyCodeApi.as_view(),
         name='forget-password-verification-code'),
    path('setnewpassword/', account_views.SetNewPasswordApi.as_view(), name='set-new-password'),
    path('changepassword/', account_views.ChangePassword.as_view(), name='change_password'),
]


def get_login_url():
    return reverse("user-login")


def get_register_url():
    return reverse("register-user")


def get_verify_email_url(username, code):
    return reverse("email-verify", kwargs={"username": username, "code": code})


def get_reset_password_url():
    return reverse("reset-password")


def send_verification_code(username):
    return reverse("send-verification-code", kwargs={"username": username})


def set_user_password(username, code):
    return reverse("set-user-password", kwargs={"username": username, "code": code})


def confirm_reset_password_code(username, code=0):
    return reverse("confirm-reset-password-code", kwargs={"username": username, "code": code})
