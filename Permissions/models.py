# from django.db import models
#
#
# class UserRole(models.Model):
#     name = models.CharField(max_length=100, unique=True)
#
#     def __str__(self):
#         return self.name
#
#
# class Action(models.Model):
#     name = models.CharField(max_length=100)
#     can_add = models.BooleanField(default=False)
#     can_edit = models.BooleanField(default=False)
#     can_delete = models.BooleanField(default=False)
#     can_view = models.BooleanField(default=False)
#     module = models.ForeignKey('Module', on_delete=models.CASCADE, null=True, blank=True)
#
#     def __str__(self):
#         return self.name
#
#
# class Module(models.Model):
#     name = models.CharField(max_length=100)
#
#     def __str__(self):
#         return self.name
#
#
# class Permission(models.Model):
#     module = models.ManyToManyField(Action)
#     default_permissions = models.BooleanField(null=False, blank=False, default=False)
#     role = models.ForeignKey(UserRole, on_delete=models.CASCADE, null=True, blank=True)
#
#     def __str__(self):
#         return self.role.name


from django.contrib.auth.models import User
from django.db import models
from Account import models as account_models


class UserRole(models.Model):
    name = models.CharField(max_length=50, unique=True)
    permissions = models.ManyToManyField('ModulePermission')
    actual_roles = models.BooleanField(default=False)

    # users = models.ManyToManyField(User)

    def __str__(self):
        return self.name


class ModulePermission(models.Model):
    module_name = models.CharField(max_length=50)
    can_add = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    can_view = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.module_name}---{', '.join(permission.name for permission in self.userrole_set.all())}"


class UserRolePermission(models.Model):
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE)
    user = models.ForeignKey(account_models.UserProfile, on_delete=models.CASCADE, unique=True, null=True, blank=True)
    default_permission = models.BooleanField(default=False)

    def __str__(self):
        if not self.default_permission:
            try:
                return self.user.role + "-------" + self.user_role.name
            except:
                return 'No ROLE Defined In UserProfile MOdel for this user' + "-------" + self.user_role.name
        else:
            return self.user.user.get_full_name() + "-------" + self.user_role.name
