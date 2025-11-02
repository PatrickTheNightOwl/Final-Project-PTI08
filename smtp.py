import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import os
def generate_otp() :
    otp = ""
    for i in range(6) :
        otp += str(random.randint(0,9))
    return otp

def send_otp(receiver_email,username,otp) :
    server = smtplib.SMTP("smtp.gmail.com",587)
    sender_email = "s"
    sender_password = os.getenv("EMAIL_PASSWORD")
    server.starttls()
    server.login(sender_email,sender_password)
    
    email_subject = f"Your One-Time Password (OTP) for TrainAnywhere"

    email_body = f"""
    Hi {username},

    Your One-Time Password (OTP) is:

    **{otp}**

    Do not share this code with anyone.

    If you did not request this, please ignore this email.

    Thank you,
    TrainAnywhere Team
    """
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = email_subject
    msg.attach(MIMEText(email_body,"html"))
    server.sendmail(sender_email,receiver_email,msg.as_string())
    server.quit()