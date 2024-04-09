# import self as self
# from rest_framework.serializers import ModelSerializer
# from Account import models as account_models
# from rest_framework import serializers
# from django.contrib.auth.models import User
# from . import models as permission_models
#
#
# class RoleSerializer(serializers.ModelSerializer):
#
#     def to_representation(self, instance):
#         # Customize representation for GET request
#         data = super().to_representation(instance)
#         data['name'] = data['name'].title()  # Convert 'name' to title case
#         return data
#
#     def save(self, **kwargs):
#         # Convert 'name' to lowercase
#         self.validated_data['name'] = self.validated_data['name'].lower()
#
#         # Check if the name already exists
#         if permission_models.UserRole.objects.filter(name=self.validated_data['name']).exists():
#             raise serializers.ValidationError("Name already exists.")
#         return super().save(**kwargs)
#
#     class Meta:
#         model = permission_models.UserRole
#         fields = '__all__'
#
#
# class ActionSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = permission_models.Action
#         fields = '__all__'
#
#
# class ModuleSerializer(serializers.ModelSerializer):
#     actions = serializers.SerializerMethodField('get_actions', read_only=True)
#
#     def get_actions(self, obj):
#         actions = permission_models.Action.objects.filter(module=obj)
#         return ActionSerializer(actions, many=True).data
#
#     class Meta:
#         model = permission_models.Module
#         fields = '__all__'
#
#
# class PermissionSerializer(serializers.ModelSerializer):
#     module = ModuleSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = permission_models.Permission
#         exclude = ('role',)


from rest_framework import serializers
from .models import UserRole, ModulePermission, UserRolePermission


class GetUserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = ('id', 'name',)


class UserRolePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRolePermission
        fields = '__all__'


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ModulePermission
        fields = '__all__'


class UserRoleSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField('get_permissions', read_only=True)

    def get_permissions(self, obj):
        permissions = obj.permissions.all()
        serializers_data = PermissionSerializer(permissions, many=True).data
        return serializers_data

    class Meta:
        model = UserRole
        fields = '__all__'
