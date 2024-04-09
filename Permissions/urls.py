from django.urls import path, reverse
from . import views as permission_views

urlpatterns = [
    # path('role/', permission_views.Role.as_view(), name='role'),
    # path('permission/', permission_views.Permission.as_view(), name='permission'),
    path('userrolelist/', permission_views.UserRoleList.as_view(), name='role-list'),
    path('userrolelist/<int:pk>', permission_views.UserRoleList.as_view(), name='role-list'),
    path('userroledetails/<int:pk>', permission_views.UserRoleDetail.as_view(), name='role-detail'),
    #     -----------------------------
    path('permissions/', permission_views.PermissionList.as_view()),
    path('roles/<int:pk>/permissions/', permission_views.RolePermissionList.as_view()),
    path('users/<int:pk>/permissions/', permission_views.UserPermissionList.as_view()),
    # Permission Assignment
    path('roles/<int:pk>/add-permission/', permission_views.AddRolePermission.as_view()),
    path('users/<int:pk>/add-permission/', permission_views.AddUserPermission.as_view()),
]
