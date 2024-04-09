from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=False, null=False)
    phone = models.CharField(max_length=60, null=True, blank=True)
    email_verified = models.BooleanField(null=False, blank=False, default=False)
    verification_code = models.IntegerField(null=True, blank=True)
    # permission = models.ManyToManyField(permission_models.Permission, blank=True)
    role = models.CharField(max_length=60, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        try:
            return "{}".format(self.user.get_full_name())
        except:
            return "{}".format(self.user.id)

    @property
    def name(self):
        return self.user.get_full_name()

    @property
    def email(self):
        return self.user.email
