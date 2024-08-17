from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import User, Otp
from django.utils import timezone

# import datetime
import pytz
from django.core.mail import send_mail
from .create_key import generateOTP
from django.contrib.auth.hashers import check_password
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
import logging

utc = pytz.UTC

# creating a logger
logger = logging.getLogger(__name__)


# Create your views here.
def index(request):
    
    return render(request, "perfumes/index.html")


def login_view(request):
    if request.method == "POST":
        
        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(
                request,
                "perfumes/login.html",
                {"message": "Invalid username and/or password."},
            )

        old = user.password

        if check_password(password, old):
            try:
                # user0 = User.objects.get(username=username)
                if user.is_active == False:
                    messages.error(
                        request, "Your account is locked.\n Please verifey your email"
                    )
                    return redirect(forgot_pass)

                elif user.attempts >= 3:
                    user.is_active = False
                    user.save()
                    messages.error(
                        request, "Your account is locked.\n Please verifey your email"
                    )
                    return redirect(forgot_pass)

                elif user.logged_in == True:

                    otp = Otp.objects.filter(user=user).last()
                    otp.delete()
                    otp = Otp.objects.create(
                        user=user, otp_code=generateOTP(user.username)
                    )
                    subject = "Email Verification"
                    message = f"""
                            Hi {user.username}, we detected an attemp to login on another device here is your otp: {otp.otp_code}.\n
                            valid for only 5 minutes. Verify if it's you here or just ignore it if it wasn't you:
                            http://127.0.0.1:8000/verify-email/{user.id}
                        """
                    sending = "erenyaarmin5000@gmail.com"
                    receiving = [user.email]

                    send_mail(subject, message, sending, receiving, fail_silently=False)

                    return redirect(verify_otp, user.pk, 0, 1)

            except User.DoesNotExist:
                return render(
                    request,
                    "perfumes/login.html",
                    {"message": "Invalid username and/or password."},
                )
        # user = authenticate(request, username=username, password=password)
        else:
            user = User.objects.get(username=username)
            user.attempts += 1
            logger.warning(f"{user.username} : incorrect attempt to login!")
            user.save()
            return render(
                request,
                "perfumes/login.html",
                {"message": "Invalid username and/or password."},
            )
        # Check if authentication successful
        user = authenticate(request, username=username, password=password)
        if user is not None:
            logger.info(f"{user.username} logged in!")
            user.logged_in = True
            user.device += 1
            user.save()
            login(request, user)
            return HttpResponseRedirect(reverse("index"))
        # else:
        #     user0.attempts += 1
        #     logger.warning(f"{user0.username} : incorrect attempt to login!")
        #     user0.save()
        #     return render(
        #         request,
        #         "perfumes/login.html",
        #         {"message": "Invalid username and/or password."},
        #     )
    else:
        return render(request, "perfumes/login.html")


def logout_view(request):
    try:
        user = request.user
        if user.device == 1:
            user.logged_in = False
            user.device -= 1
            user.save()
    except Exception:
        return HttpResponseRedirect(reverse("index"))
    logger.info(f"{user.username} logged out!")
    
    logout(request)
    return HttpResponseRedirect(reverse("index"))


def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        phone = request.POST["phone"]

        # preventing duplicate accounts using same email
        if User.objects.filter(email=email).exists():
            messages.error(request, "This email is already in use!")
            return redirect(register)

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            return render(
                request, "perfumes/register.html", {"message": "Passwords must match."}
            )
        
        # Attempt to create new user
        try:
            user = User.objects.create_user(username, email, password)
            user.is_active = False
            user.save()
            return redirect(verify_otp, user.id, 0, 0)
        except IntegrityError:
            return render(
                request,
                "perfumes/register.html",
                {"message": "Username already taken!"},
            )

    else:
        return render(request, "perfumes/register.html")


def verify_otp(request, id, forgot, another_device=0):
    curr_user = User.objects.get(id=id)
    if request.method == "POST":
        otp = Otp.objects.filter(user=curr_user.id).last()
        if otp.otp_code == request.POST["otp"]:
            # if otp not expired
            if otp.expires_at > timezone.now():
                # if user forgot password
                if forgot == 1:
                    messages.success(request, curr_user)
                    return redirect(change_password)

                elif another_device == 1:
                    curr_user.device += 1
                    curr_user.save()
                    login(request, curr_user)
                    return HttpResponseRedirect(reverse("index"))

                curr_user.is_active = True
                curr_user.save()
                logout(request)

                # out of forget password
                logger.info(
                    f"Account for {curr_user.username} with email : {curr_user.email} was verified"
                )

                return redirect(login_view)
            # if otp expired
            else:
                messages.error(request, "OTP expired, please request a new one")
                return redirect(verify_otp, curr_user.id, 0, another_device)
        # if otp not correct
        else:
            return redirect(verify_otp, curr_user.id, 0, another_device)
    # on get request
    if forgot == 1:
        return render(request, "perfumes/verify-f.html", {"user": curr_user})
    return render(
        request, "perfumes/verify.html", {"user": curr_user, "device": another_device}
    )


def re_otp(request, id, forgot, device):
    curr_user = User.objects.get(id=id)
    otp = Otp.objects.filter(user=curr_user).last()
    otp.delete()
    otp = Otp.objects.create(user=curr_user, otp_code=generateOTP(curr_user.username))
    subject = "Email Verification"
    message = f"""
                        Hi {curr_user.username}, here is your otp: {otp.otp_code}.
                        valid for only 5 minutes. Use it to verify your account here:
                        http://127.0.0.1:8000/verify-email/{curr_user.id}
                """
    sending = "erenyaarmin5000@gmail.com"
    receiving = [curr_user.email]

    send_mail(subject, message, sending, receiving, fail_silently=False)
    logger.info(
        f"the account {curr_user.username} with email : {curr_user.email} requested another OTP"
    )

    if forgot == 0:
        return redirect(verify_otp, curr_user.id, 0, device)
    elif device > 0:
        return redirect(verify_otp, curr_user.id, 0, device)
    else:
        return redirect(verify_otp, curr_user.id, 1)


def forgot_pass(request):
    if request.method == "POST":
        email = request.POST["email"]
        try:
            curr_user = User.objects.get(email=email)
            logger.info(
                f"the account {curr_user.username} with email : {curr_user.email} forgot the password!"
            )
            otp = Otp.objects.create(
                user=curr_user, otp_code=generateOTP(curr_user.username)
            )
            subject = "Email Verification"
            message = f"""
                            Hi {curr_user.username}, here is your otp: {otp.otp_code}.
                            valid for only 5 minutes. Use it to change your password here:
                            http://127.0.0.1:8000/change-pass/{curr_user.id}
                    """
            sending = "erenyaarmin5000@gmail.com"
            receiving = [curr_user.email]
            send_mail(subject, message, sending, receiving, fail_silently=False)
            logger.info(
                f"the account {curr_user.username} with email : {curr_user.email} recieved an OTP"
            )
            curr_user.is_active = False
            curr_user.save()
            return render(request, "perfumes/verify-f.html", {"user": curr_user})
        except ObjectDoesNotExist:
            messages.error(request, "We found no account associated with this email.")
            return redirect(forgot_pass)

    return render(request, "perfumes/forgot.html")


def change_password(request):
    if request.method == "POST":
        # getting the user
        user = User.objects.get(username=request.POST["id"])
        # collecting old password hash from database for comparison with the new password
        old = user.password
        new = request.POST["pass"]
        confirmation = request.POST["pass2"]
        # checking that the user typed the password correctly and throwing an error if not
        if not new == confirmation:
            return render(
                request,
                "perfumes/pass.html",
                {
                    "message": "the password and the confirmation don't match",
                    "user": user,
                },
            )
        # checking if the user typed the old password and throwing an error if so
        elif check_password(new, old):
            return render(
                request,
                "perfumes/pass.html",
                {"message": "don't use the same password", "user": user},
            )
        # saving the new password
        else:
            user.set_password(new)
            user.is_active = True
            user.attempts = 0
            user.save()
            logout(request)
            messages.success(
                request, "Password changed successfully, please log in again"
            )
            logger.info(
                f"the account {user.username} with email : {user.email} changed the password"
            )
            return redirect(login_view)
    # in case of get request
    else:
        return render(
            request,
            "perfumes/pass.html",
        )


# failed attempt, LEAVE AS IS
# def attempts(request, password, username, att):
#     try:
#         user = User.objects.get(username=username)

#     except User.DoesNotExist:
#         return render(
#             request,
#             "perfumes/login.html",
#             {"message": "This username does not exist!"},
#         )
#     # collecting old password hash from database for comparison with the new password
#     old = user.password
#     if not check_password(password, old):

#         if int(att) >= 3:
#             user.is_active = False
#             user.save()
#             messages.error(
#                 request, "Your account is locked.\n Please verifey your email"
#             )
#             return JsonResponse(["new"], safe=False), redirect(forgot_pass)
#         else:
#             return JsonResponse(["False"], safe=False)
#     else:
#         return JsonResponse(["True"], safe=False)
