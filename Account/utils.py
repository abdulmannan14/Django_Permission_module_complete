from random import randint
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework_jwt.settings import api_settings

from . import urls as view_urls
from threading import Thread
from .models import UserProfile

from .models import User, UserProfile
from permission_module import utils as backend_utils
from Permissions import models as permission_models, serializers as permission_serializers, utils as permission_utils


def get_user_profile(username=None, code=None, email=None):
    try:
        if username and code:
            return UserProfile.objects.get(user__username=username, verification_code=code)
        if email and code:
            return UserProfile.objects.get(user__email=email, verification_code=code)
        if username:
            return UserProfile.objects.get(user__username=username)
        if email:
            return UserProfile.objects.get(user__email=email)
        if code:
            return UserProfile.objects.get(verification_code=code)

        backend_utils.logger("Username or email not provided!")
        return None
    except UserProfile.DoesNotExist as exep:
        backend_utils.logger(str(exep))
        return None


def get_company_from_user(user):
    """
    get company object from authenticated user
    param: user
    """
    try:
        return user.userprofile.employeeprofilemodel.company
    except:
        return user.userprofile.personalclientprofilemodel.company

    # finally:
    #     return user.userprofile.personalclientprofilemodel.company


def get_token(user):
    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
    payload = jwt_payload_handler(user)
    return jwt_encode_handler(payload)


def random_digits():
    range_start = 10 ** (4 - 1)
    range_end = (10 ** 4) - 1
    return randint(range_start, range_end)


def get_full_url(request, path):
    return "{}://{}{}".format(request.scheme, request.get_host(), path)


def thread_making(target, arguments: list):
    t = Thread(target=target,
               args=arguments)
    t.setDaemon(True)
    t.start()


def get_user(username: str = None, email: str = None):
    try:
        if username:
            return User.objects.get(username=username.lower())
        if email:
            return User.objects.get(email=email.lower())
        backend_utils.logger("Username or email not provided!")
        return None
    except User.DoesNotExist as exep:
        backend_utils.logger(str(exep))
        return None


def create_user_profile(user: User, email_verified=False):
    return UserProfile.objects.create(user=user, verification_code=random_digits(), email_verified=email_verified)


def get_all_permissions(user):
    # try:
    print("====as=sa=s=a=sa=")
    all_permissions = permission_models.UserRolePermission.objects.get(
        user=user.userprofile)
    print(all_permissions, "all_permissions")
    default = all_permissions.default_permission
    if default:
        all_permissions = permission_models.UserRole.objects.filter(name=all_permissions.user_role).first()
    else:
        all_permissions = permission_models.UserRole.objects.filter(name=all_permissions.user.role).first()
    print(all_permissions, "aaaaaaa")
    serializer = permission_serializers.UserRoleSerializer(all_permissions)
    json_data = permission_utils.convert_serialized_data_to_json(serializer.data)
    print("this is json data", json_data)
    if json_data.get("permissions"):
        returning_data = permission_utils.compare_and_update_permissions(json_data)
    else:
        returning_data = permission_utils.send_default_permissions()
    return returning_data
    # except Exception as e:
    #     print("====EXCEPRIONS IS===", e)
    #     return None
