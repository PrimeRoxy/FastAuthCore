# Function to generate a 4-digit OTP
import logging
import mimetypes
import string
import traceback
import boto3
import httpx
import json
import requests
from dotenv import load_dotenv
import os
import random
from sqlalchemy.orm import Session
from fastapi import Depends
from sqlalchemy.exc import IntegrityError
from models import EmailOTPs,Role
from models import EmailOTPs, OTPs, Role
from fastapi import HTTPException, status
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from twilio.rest import Client
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set up email credentials (using environment variables for security)
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_PORT = os.getenv("SMTP_PORT")
OTP_EMAIL_TEMPLATE = os.getenv('OTP_EMAIL_TEMPLATE')
SCHEDULAR_API = os.getenv('SCHEDULAR_API')
EMAIL_API = os.getenv('EMAIL_API')

# Load environment variables
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_SERVICE_ID = os.getenv('TWILIO_SERVICE_ID')

# Load environment variables
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("S3_REGION","us-east-1")
S3_BUCKET_NAME = os.getenv("AWS_S3_BUCKET", "tulahdocument")

# Set up email credentials (using environment variables for security)
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_PORT = os.getenv("SMTP_PORT")
# Base_url = os.getenv('BASE_URL')
EMAIL_TEMPLATE = os.getenv('EMAIL_TEMPLATE')

# Define the SMTP server settings
smtp_server = "smtp.gmail.com"
smtp_port = SMTP_PORT

# Get Kaleyra credentials from environment variables
KALEYRA_API_KEY = os.getenv("SSO_KALEYRA_API_KEY")
KALEYRA_SID = os.getenv("SSO_KALEYRA_SID")
SENDER_ID = os.getenv('SENDER_ID')
TEMPLATE_ID = os.getenv('TEMPLATE_ID')
MESSAGE_TEMPLATE = os.getenv('MESSAGE_TEMPLATE')

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def seed_roles(db: Session):
    roles_to_seed = os.getenv("ROLES", "").split(",")  # Add more roles as needed
    
    for role_name in roles_to_seed:
        # Check if the role already exists
        existing_role = db.query(Role).filter_by(role_name=role_name).first()
        if not existing_role:
            # If the role does not exist, create a new Role instance and add it to the session
            new_role = Role(role_name=role_name)
            db.add(new_role)

    try:
        # Commit the transaction if there were any new roles added
        db.commit()
    except IntegrityError:
        # In case of any integrity errors (e.g., unique constraints), rollback the transaction
        db.rollback()

# Initialize Twilio client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_otp(phone_number):
    """Send an OTP to the specified phone number."""
    try:
        verification = client.verify.v2.services(TWILIO_SERVICE_ID).verifications.create(
            to=phone_number,   # recipient phone number
            channel='sms'      # specify 'sms'
        )
        print(f"SMS sent with status: {verification.status}")
        return verification.status  # Return the status for further processing
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return None

def verify_otp_twilio(phone_number, code):
    """Verify the OTP for the specified phone number."""
    try:
        verification_check = client.verify.v2.services(TWILIO_SERVICE_ID).verification_checks.create(
            to=phone_number,
            code=code
        )
        print(f"Verification status: {verification_check.status}")
        return verification_check.status  # Return the status for further processing
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return None
    
def get_auth_token():
    """
    Retrieve the authentication token from the SCHEDULAR API.
    """
    url = f"{SCHEDULAR_API}/api/v1/auth/token"
    try:
        response = requests.post(url)  # Modify if auth requires credentials
        response.raise_for_status()
        token = response.json().get("access_token")
        if token:
            return token
        else:
            print("Failed to retrieve access token")
            return None
    except requests.RequestException as e:
        print("Error retrieving auth token:", e)
        return None

def send_user_data_to_SCHEDULAR_API(user_id: str, firstname: str, lastname: str, role_ids: list):
    
    url = f"{SCHEDULAR_API}/api/v1/users/"  
    auth_token = get_auth_token()
    if not auth_token:
        print("Authorization failed. Cannot send user data.")
        return None
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }
    # Ensure full_name is properly formatted and not empty
    full_name = " ".join(filter(None, [firstname, lastname])).strip()
    if not full_name:
        print("Error: full_name is empty")
        return None
    # Prepare the data payload
    payload = {
        "user_id": user_id,
        "name": full_name,
        "role_ids": role_ids
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        if response.status_code == 400:
            print(f"User '{user_id}' already exists in SCHEDULAR_API.")
            return {"message": "User already exists"}
        
        print("User data sent to SCHEDULAR_API successfully:", response.json())
    except requests.RequestException as e:
        print("Failed to send user data to SCHEDULAR_API:", e)


def send_role_data_to_SCHEDULAR_API(role_id: int, role_name: str):
    url = f"{SCHEDULAR_API}/api/v1/roles/"
    auth_token = get_auth_token()
    if not auth_token:
        print("Authorization failed. Cannot send user data.")
        return None
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }
    payload = {
        "role_id": role_id,
        "role_name": role_name
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print("Role data sent successfully:", response.json())
        return response.json()
    except requests.RequestException as e:
        print("Failed to send role data to SCHEDULAR API:", e)
        return None
    
def create_calendar(user_id: str):
    auth_token = get_auth_token()
    if not auth_token:
        print("Authorization failed. Cannot create calendar.")
        return None
    url = f"{SCHEDULAR_API}/api/v1/calender/calendar/{user_id}"
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()  
        if response.status_code == 400:
            print(f"Calendar for user '{user_id}' already exists in SCHEDULAR_API.")
            return {"message": "Calendar already exists"}
        response.raise_for_status()
        print("Calendar created successfully:", response.json())
        return response.json()
    except requests.RequestException as e:
        print("Failed to create calendar:", e)
        return None

async def send_email_otp(to_email: str,db):
    """Sends OTP via email and stores it in the database."""
    otp = generate_otp()
    expiration_time = datetime.now() + timedelta(minutes=10)

    # Check if OTP for the email already exists
    existing_otp = db.query(EmailOTPs).filter(EmailOTPs.email == to_email)
    
    if existing_otp.first():
        # Update existing OTP in the database
        existing_otp.update({"otp": otp, "expires_at": expiration_time}, synchronize_session=False)
    else:
        # Store the new OTP in the database
        new_otp = EmailOTPs(
            email=to_email,
            otp=otp,
            expires_at=expiration_time,
        )
        db.add(new_otp)
    
    db.commit()

    url = f"{EMAIL_API}/send-email"
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'recipient': to_email,
        'subject': 'OTP Verification',
        'email_type': 'OTP',
        'text_body': '',
        'dynamic_data': f'{{"otp":"{otp}"}}'
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, data=data)
        if response.status_code == 200:
            return response.json().get('message')
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to send OTP email")


def get_s3_client():
    """
    Initialize and return an AWS S3 client.
    """
    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        raise HTTPException(status_code=401, detail="AWS credentials are not set")
    
    return boto3.client(
        service_name="s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )


def upload_file_to_s3(file_obj, bucket_name, file_name):
    """
    Upload a file to an S3 bucket and return the public URL of the file.
    """
    s3_client = get_s3_client()
    try:
        # Determine the file's MIME type
        content_type, _ = mimetypes.guess_type(file_name)
        if not content_type:
            content_type = "application/octet-stream"  # Default if type can't be guessed

        # Upload the file with proper Content-Type
        s3_client.upload_fileobj(
            file_obj.file,
            bucket_name,
            file_name,
            ExtraArgs={"ContentType": content_type, "ACL": "public-read"}  # Make the file publicly readable
        )

        # Generate public URL for the uploaded file
        document_url = f"https://{bucket_name}.s3.{AWS_REGION}.amazonaws.com/{file_name}"
        return document_url
    except NoCredentialsError:
        raise HTTPException(status_code=401, detail="AWS credentials not found")
    except PartialCredentialsError:
        raise HTTPException(status_code=401, detail="Incomplete AWS credentials")
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Error uploading file to S3: {str(err)}")

# Function to create a custom email template with URL
def create_email_template_for_url(url: str) -> str:
    template = EMAIL_TEMPLATE.format(set_new_password_link=url)
    return template

async def send_email(email: str, url: str):
    try:
        # Create the email content
        subject = "Password Reset Request"
        body = create_email_template_for_url(url)
        # Create a MIMEText object to represent the email
        message = MIMEMultipart("alternative")
        message["From"] = SMTP_USER
        message["To"] = email
        message["Subject"] = subject

        # Attach the HTML body to the email
        body_part = MIMEText(body, "html", _charset="utf-8")
        message.attach(body_part)

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, email, message.as_string())

        return {"message": "Link Send For Reset Forget Password"}

    except smtplib.SMTPAuthenticationError as auth_error:
        logger.error(f"SMTP Authentication Error: {str(auth_error)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=401, detail=f"Authentication Error: {auth_error}")
    except smtplib.SMTPException as smtp_error:
        logger.error(f"SMTP Error: {str(smtp_error)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"SMTP Error: {smtp_error}")
    except Exception as e:
        logger.error(f"Failed to send reset link: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to send reset link: {e}")


# async def send_otp_phone_kaleyra(phone_number: str, db):
#     """Sends OTP via phone using the Kaleyra API and stores it in PostgreSQL."""
#     otp = generate_otp()
#     try:
#         url = f"https://api.kaleyra.io/v1/{KALEYRA_SID}/messages"
#         headers = {
#             "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
#             "api-key": KALEYRA_API_KEY,
#         }
#         # Format the message using the template from .env
#         body = MESSAGE_TEMPLATE.format(otp=otp)
        
#         data = {
#             # "to": f"+91{phone_number}",
#             "to": phone_number,
#             "type": "OTP",
#             "sender": SENDER_ID,
#             "body": body,
#             "template_id": TEMPLATE_ID,
#         }

#         response = requests.post(url, headers=headers, data=data)
#         if response.status_code // 100 == 2:
#             # Store OTP in PostgreSQL with an expiration time
#             otp_expiration_time = datetime.now() + timedelta(minutes=5)
#             existing_otp = db.query(OTPs).filter(OTPs.phone_number == phone_number)
#             if existing_otp.first():
#                 existing_otp.update({"otp": otp, "expires_at": otp_expiration_time}, synchronize_session=False)
#                 db.commit()
#             else:
#                 otp_data = OTPs(phone_number = phone_number, otp = otp, expires_at = otp_expiration_time)
#                 db.add(otp_data)
#                 db.commit()
#                 db.refresh(otp_data)
#             return {"status": "success", "message": "OTP sent successfully"}
#         else:
#             logger.error(f"Failed to send OTP via SMS. Status code: {response.status_code}, Response: {response.text}")
#             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send OTP via SMS")
#     except Exception as e:
#         logger.error(f"Error sending OTP: {str(e)}\n{traceback.format_exc()}")
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))