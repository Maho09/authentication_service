from django.db import models
from django.contrib.auth.models import AbstractUser

# from .create_key import generateOTP
from django.utils import timezone

# Create your models here.


class User(AbstractUser):
    phone_number = models.CharField(max_length=20, default="")
    logged_in = models.BooleanField(default=False)
    emails = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    device = models.IntegerField(default=0)


class Otp(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_id")
    otp_code = models.CharField(max_length=8, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        default=timezone.now() + timezone.timedelta(minutes=5)
    )
