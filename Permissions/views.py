import json

from django.http import Http404
from django.shortcuts import render
from rest_framework.renderers import JSONRenderer

from . import serializers as permission_serializers, models as permission_models
from permission_module import utils as backend_utils
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
#
#
# # Create your views here.
# class Role(APIView):
#     serializer_class = permission_serializers.RoleSerializer
#     permission_classes = (AllowAny,)
#
#     def post(self, request, format=None):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         if serializer.is_valid():
#             serializer.save()
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
#                                            msg='Role Added Successfully'))
#
#     def get(self, request, format=None):
#         roles = permission_models.UserRole.objects.all()
#         serializer = permission_serializers.RoleSerializer(roles, many=True)
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=serializer.data,
#                                            msg='Roles Retrieved Successfully'))
#
#     def patch(self, request, pk, format=None):
#         role = permission_models.UserRole.objects.get(pk=pk)
#         serializer = permission_serializers.RoleSerializer(role, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
#                                            msg='Role Updated Successfully'))
#
#     def delete(self, request, pk, format=None):
#         role = permission_models.UserRole.objects.get(pk=pk)
#         role.delete()
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
#                                            msg='Role Deleted Successfully'))
#
#
# class Permission(APIView):
#     serializer_class = permission_serializers.PermissionSerializer
#     permission_classes = (AllowAny,)
#
#     def post(self, request, format=None):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
#                                            msg='Permission Added Successfully'))
#
#     def get(self, request, format=None):
#         permissions = permission_models.Module.objects.all()
#         serializer = permission_serializers.ModuleSerializer(permissions, many=True)
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=serializer.data,
#                                            msg='Permissions Retrieved Successfully'))
#
#     def patch(self, request, pk, format=None):
#         permission = permission_models.Permission.objects.get(pk=pk)
#         serializer = permission_serializers.PermissionSerializer(permission, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
#                                            msg='Permission Updated Successfully'))
#
#     def delete(self, request, pk, format=None):
#         permission = permission_models.Permission.objects.get(pk=pk)
#         permission.delete()
#         return Response(
#             backend_utils.success_response(status_code=status.HTTP_200_OK, data=None,
#                                            msg='Permission Deleted Successfully'))


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserRole, ModulePermission, UserRolePermission
from .serializers import UserRoleSerializer, PermissionSerializer, GetUserRoleSerializer
from Account import models as account_models
from . import permission as all_permissions, utils as permission_utils


class UserRoleList(APIView):
    """
    API view to get all user roles or create a new role.
    """

    def get(self, request, format=None):
        user_roles = UserRole.objects.filter(actual_roles=True)
        serializer = GetUserRoleSerializer(user_roles, many=True)
        # return Response(serializer.data)
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=serializer.data,
                                           msg='Action Successful'))

    def post(self, request, format=None):
        try:
            alloted_permissions = request.data.get('permissions')
            role_name = request.data.get('name')
            role_obj = UserRole.objects.filter(name=role_name, actual_roles=True).first()
            if role_obj:
                return Response(
                    backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                                   msg="Role Name Already Exist"))
            role_obj = UserRole.objects.create(name=role_name, actual_roles=True)
            for permission_segment in alloted_permissions:
                module_obj = ModulePermission.objects.create(module_name=permission_segment['module_name'],
                                                             can_add=permission_segment['can_add'],
                                                             can_edit=permission_segment['can_edit'],
                                                             can_delete=permission_segment['can_delete'],
                                                             can_view=permission_segment['can_view'])
                role_obj.permissions.add(module_obj)
            return Response(
                backend_utils.success_response(status_code=status.HTTP_200_OK, data=[],
                                               msg='Role Add Action Successful'))
        except:
            return Response(
                backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                               msg="Failed"))

    def patch(self, request, pk, format=None):
        role = UserRole.objects.get(pk=pk)
        alloted_permissions = request.data.get('permissions', None)
        role_name = request.data.get('name', None)
        if not role_name and not alloted_permissions:
            return Response(
                backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                               msg="Please enter either role name or permissions"))
        if role_name:
            if role_name != role.name:
                role_obj = UserRole.objects.filter(name=role_name).first()
                if role_obj:
                    return Response(
                        backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                                       msg="Role Name Already Exist"))
                role.name = role_name
                role.save()
        if alloted_permissions:
            role.permissions.all().delete()
            for permission_segment in alloted_permissions:
                module_obj = ModulePermission.objects.create(module_name=permission_segment['module_name'],
                                                             can_add=permission_segment['can_add'],
                                                             can_edit=permission_segment['can_edit'],
                                                             can_delete=permission_segment['can_delete'],
                                                             can_view=permission_segment['can_view'])
                role.permissions.add(module_obj)
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=[],
                                           msg='Role Edit Action Successful'))

    def delete(self, request, pk, format=None):
        role = UserRole.objects.get(pk=pk, actual_roles=True)
        role.permissions.all().delete()
        role.delete()
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=[],
                                           msg='Role Delete Action Successful'))


class UserRoleDetail(APIView):
    """
    API view to retrieve, update or delete a specific user role.
    """

    def get_object(self, pk):
        try:
            return UserRole.objects.get(pk=pk)
        except UserRole.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        user_role = self.get_object(pk)
        serializer = UserRoleSerializer(user_role)
        json_data = permission_utils.convert_serialized_data_to_json(serializer.data)
        returning_data = permission_utils.compare_and_update_permissions(json_data)
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=returning_data,
                                           msg='Action Successful'))

    def put(self, request, pk, format=None):
        user_role = self.get_object(pk)
        serializer = UserRoleSerializer(user_role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                backend_utils.success_response(status_code=status.HTTP_200_OK, data=serializer.data,
                                               msg='Action Successful'))
        return Response(
            backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                           msg=serializer.errors))

    def delete(self, request, pk, format=None):
        user_role = self.get_object(pk)
        user_role.delete()
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=[],
                                           msg='Action Successful'))


permissions = all_permissions.all_permissions


class PermissionList(APIView):
    """
    API view to retrieve all permissions.
    """

    def get(self, request, format=None):
        return Response(
            backend_utils.success_response(status_code=status.HTTP_200_OK, data=permissions,
                                           msg='Action Successful'))


class RolePermissionList(APIView):
    """
    API view to retrieve permissions associated with a specific role.
    """

    def get(self, request, pk, format=None):
        try:
            user_role = UserRole.objects.get(pk=pk)
            permissions = user_role.permissions.all()
            serializer = PermissionSerializer(permissions, many=True)
            # Assuming PermissionSerializer exists
            json_data = permission_utils.convert_serialized_data_to_json(serializer.data)
            returning_data = permission_utils.compare_and_update_permissions(json_data)
            return Response(
                backend_utils.success_response(status_code=status.HTTP_200_OK, data=returning_data,
                                               msg='Action Successful'))
        except UserRole.DoesNotExist:
            return Response(
                backend_utils.failure_response(status_code=status.HTTP_400_BAD_REQUEST,
                                               msg='Role not found'))


def get_user_permissions(user):
    default_permission = UserRolePermission.objects.filter(user=user, default_permission=True).first()
    print("these are the default permission=====", default_permission)
    role_permissions = None
    user_permissions = None
    if default_permission:
        permissions = UserRole.objects.filter(name=default_permission.user_role).first()
    else:
        permissions = UserRole.objects.filter(name=user.role).first()
    if permissions:
        print("these are the permissions=====", permissions)
        print("these are the permissions=====222", permissions.permissions.all())
        serializer = PermissionSerializer(permissions.permissions.all(),
                                          many=True)
        json_data = permission_utils.convert_serialized_data_to_json(serializer.data)
        returning_data = permission_utils.compare_and_update_permissions(json_data)
        return returning_data
    return "EMPTY"


class UserPermissionList(APIView):
    """
    API view to retrieve all permissions assigned to a specific user.
    """

    def get(self, request, pk, format=None):
        try:
            user = account_models.UserProfile.objects.get(user__pk=pk)
            # Get permissions from user roles with default_permission=True
            data = get_user_permissions(user)
            return Response(
                backend_utils.success_response(status_code=status.HTTP_200_OK, data=data,
                                               msg='Action Successful'))
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_gefunden)  # German for "not found"


class AddRolePermission(APIView):
    """
    API view to add a permission to a specific role.
    """

    def post(self, request, pk, format=None):
        try:
            user_role = UserRole.objects.get(pk=pk)
            permissions = request.data.get('permissions')
            if not permissions:
                return Response({'error': 'Missing permission field in request data'},
                                status=status.HTTP_400_BAD_REQUEST)
            permission = ModulePermission.objects.get(pk=permissions)
            user_role.permissions.add(permission)
            return Response(
                backend_utils.success_response(status_code=status.HTTP_200_OK, data=[],
                                               msg='Action Successful'))
        except (UserRole.DoesNotExist, ModulePermission.DoesNotExist):
            return Response(status=status.HTTP_404_NOT_FOUND)


class AddUserPermission(APIView):
    """
    API view to assign a specific permission to a user, overriding default role permissions.
    """

    def post(self, request, pk, format=None):
        try:
            user = User.objects.get(pk=pk)
            permission_id = request.data.get('permission_id')
            if not permission_id:
                return Response({'error': 'Missing permission_id field in request data'},
                                status=status.HTTP_400_BAD_REQUEST)
            permission = ModulePermission.objects.get(pk=permission_id)
            # Check if permission already exists for the user (overrides default role permissions)
            existing_permission = UserRolePermission.objects.filter(user=user,
                                                                    user_role__permissions=permission).exists()
            if existing_permission:
                return Response({'error': 'Permission already assigned to user'}, status=status.HTTP_400_BAD_REQUEST)
            # Create a new UserRolePermission for the user and permission
            user_role_permission = UserRolePermission.objects.create(user=user, user_role=None, permission=permission,
                                                                     default_permission=False)
            return Response(
                backend_utils.success_response(status_code=status.HTTP_200_OK, data=[],
                                               msg='Action Successful'))
        except (User.DoesNotExist, ModulePermission.DoesNotExist):
            return Response(status=status.HTTP_404_NOT_FOUND)
