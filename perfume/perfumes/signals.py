from django.db.models.signals import post_save
from .models import Otp
from django.conf import settings
from django.dispatch import receiver
from django.core.mail import send_mail
from .create_key import generateOTP
from .views import logger


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_otp(sender, instance, created, **kwargs):
    if created:
        if instance.is_superuser:
            pass
        else:
            Otp.objects.create(user=instance, otp_code=generateOTP(instance.username))

            instance.save()
        otp = Otp.objects.filter(user=instance).last()
        subject = "Email Verification"
        message = f"""
                        Hi {instance.username}, here is your otp: {otp.otp_code}.
                        valid for only 5 minutes. Use it to verify your account here:
                        http://127.0.0.1:8000/verify-email/{instance.id}
                """
        sending = "erenyaarmin5000@gmail.com"
        receiving = [instance.email]

        send_mail(subject, message, sending, receiving, fail_silently=False)

        logger.info(f"OTP was sent to verify {instance.email}")
