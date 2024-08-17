from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("register", views.register, name="register"),
    path("verifey-otp/<int:id>/<int:forgot>/<int:another_device>", views.verify_otp ,name="verify-otp"),
    path("re-otp/<int:id>/<int:forgot>/<int:device>", views.re_otp ,name="re-otp"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout_view"),
    path("change-pass", views.change_password, name="change-pass"),
    path("forgot-pass", views.forgot_pass, name="forgot-pass"),
    # path("attempts/<str:password>/<str:username>/<str:att>", views.attempts, name="attempts")
]
