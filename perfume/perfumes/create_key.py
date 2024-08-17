import math, random


# function to generate OTP
def generateOTP(user):
    user_val = 0
    for i in range(len(user)):
        user_val += ord(user[i])
    string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    OTP1 = ""
    length = len(string)
    for i in range(8):
        OTP1 += string[math.floor(random.random() * length)]
    OTP = "".join([str(random.randint(0, 9)) for _ in range(8)])
    OTP = str(user_val) + OTP[0:3] + OTP1[5:7]

    return OTP
