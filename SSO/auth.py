import os
import logging
import traceback
from typing import List, Optional
import uuid
from fastapi import APIRouter, File, HTTPException, Depends, UploadFile, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import EmailStr
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import random
import string
from database import get_db
from models import Role, User, EmailOTPs
from schemas import CustomResponse,AddUser, CustomuserResponse, RoleResponse, RoleUpdateSchema, UserIDsResponse,CustomRoleResponse,PermissionsUpdateSchema, RoleCreateSchema, RoleResponseSchema, SetNewPassword, UserSchema, OTPRequest, OTPVerify, PasswordReset, UserSignInSchema, EmailOtp,EmailOTPVerify,UserUpdateSchema,UserResponse,PasswordForget
from sqlalchemy.orm import Session
from utils import S3_BUCKET_NAME, create_calendar, send_email_otp, send_role_data_to_SCHEDULAR_API, upload_file_to_s3,verify_otp_twilio,send_otp,send_user_data_to_SCHEDULAR_API,send_email
from service import (
    generate_otp,
    generate_token,
    generate_refresh_token,
    verify_password,
    get_password_hash,
    authenticate_user,
    get_user,
    get_current_user,
)

router = APIRouter()
# Configure the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get Kaleyra credentials from environment variables
KALEYRA_API_KEY = os.getenv("SSO_KALEYRA_API_KEY")
KALEYRA_SID = os.getenv("SSO_KALEYRA_SID")
SENDER_ID = os.getenv('SENDER_ID')
TEMPLATE_ID = os.getenv('TEMPLATE_ID')
MESSAGE_TEMPLATE = os.getenv('MESSAGE_TEMPLATE')
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")



# ---------------------------
# Authentication Endpoints
# ---------------------------


# this is the APi to create a new user
@router.post("/signup")
async def signup(user: UserSchema, db: Session = Depends(get_db)):
    # Check if the user already exists by email or phone number
    existing_user = db.query(User).filter(
        (User.email == user.email) | (User.phone_number == user.phone_number)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash the user's password
    hashed_password = get_password_hash(user.password)
    
    # Determine the roles (Super Admin if role_id is 0, otherwise defaults to role_id 1)
    if hasattr(user, 'role_ids') and user.role_ids:
        role_ids = user.role_ids
    else:
        if hasattr(user, 'role_id') and user.role_id == 0:
            role_ids = [0]  # Super admin role
        else:
            role_ids = [user.role_id] if hasattr(user, 'role_id') and user.role_id else [1]  # Default to role_id 1
    
    # Fetch the roles based on the provided role_ids
    roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
    
    # Check if any roles are missing
    if not roles and 0 in role_ids:
        # If no roles are found and super admin is requested, create a super admin role if it doesn't exist
        super_admin_role = Role(id=0, role_name="Super Admin", permissions=[{"all_permissions": 0}])
        db.add(super_admin_role)
        db.commit()
        db.refresh(super_admin_role)
        roles = [super_admin_role]

    # Set the profile image to default if none is provided
    default_profile_image = "https://tulahdocument.s3.us-east-1.amazonaws.com/13b23446-f791-4b65-a46e-4df86ecdf478.webp"
    source_profile = user.source_profile if user.source_profile else default_profile_image
    
    # Create a new user and assign the roles
    db_user = User(
        firstname=user.firstname,
        lastname=user.lastname,
        email=user.email,
        phone_number=user.phone_number,
        hashed_password=hashed_password,
        roles=roles,  # Assign roles to the user
        source_profile=source_profile  # Set the user profile image
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Prepare data for the access token
    data = {
        "user_id": db_user.uuid,
        "email": db_user.email, 
        "phone_number": db_user.phone_number,
        "role_ids": [role.id for role in db_user.roles]  # Include multiple role IDs
    }

    # Generate access token and refresh token for the user
    access_token = generate_token(data=data)
    refresh_token = generate_refresh_token(data=data)
    db_user.access_token = access_token
    db.commit()

    # Call the SCHEDULAR API after user creation
    send_user_data_to_SCHEDULAR_API(db_user.uuid, db_user.firstname, db_user.lastname, [role.id for role in db_user.roles])
    create_calendar(db_user.uuid)

    return {
        "msg": "User registered and signed in successfully",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": db_user.uuid,
        "role_ids": [role.id for role in db_user.roles],  # Return role IDs in response
        "source_profile": db_user.source_profile  # Return the profile image
    }

# this is the API to Sign in a user using email and password
@router.post("/signin")
async def signin(user: UserSignInSchema, response: JSONResponse, db: Session = Depends(get_db)):
    # Authenticate the user
    authenticated_user = await authenticate_user(user.email, user.password, db=db)

    if not authenticated_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # Collect the user's role IDs (since a user can have multiple roles)
    role_ids = [role.id for role in authenticated_user.roles]

    # Create token data
    data = {
        "user_id": authenticated_user.uuid,  # User UUID
        "email": authenticated_user.email,
        "phone_number": authenticated_user.phone_number,
        "role_ids": role_ids  # List of role IDs
    }

    # Generate the access token
    access_token = generate_token(data=data)

    # Generate the refresh token
    refresh_token = generate_refresh_token(data=data)

    # Store the access token in the user record
    authenticated_user.access_token = access_token
    db.commit()

    # Set the refresh token in a secure HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,        # Prevents access to the cookie via JavaScript
        secure=True,          # Ensures the cookie is only sent over HTTPS
        # samesite="strict",    # Helps mitigate CSRF attacks
        samesite=None,
        max_age=3 * 24 * 60 * 60  # Set expiration to 3 days 
    )

    # Return the access token and user info in the response body
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": authenticated_user.uuid,  # User UUID in the response
        "role_ids": role_ids  # List of role IDs in the response
    }


# Send the OTP to the user's email
@router.post("/request-otp")
async def request_otp(otp_request: EmailOtp, db: Session = Depends(get_db)):
    try:
        # Check if the phone number exists in the User table
        user = db.query(User).filter(User.email == otp_request.email).first()
        if not user:
            return {
                "message": "User does not exist.",
                "results": None,
                "status": 404,
                "errors": "Email not found in the system."
            }
        await send_email_otp(otp_request.email, db)
        return {"msg": f"OTP sent to {otp_request.email}"}
    except Exception as e:
        logger.error(f"Failed to send OTP: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to send OTP")

# Verify the OTP sent to the user's email
@router.post("/verify-otp")
async def verify_otp(otp_verify: EmailOTPVerify, response: JSONResponse,db: Session = Depends(get_db)):
    """Verify the OTP sent to the user's phone number."""
    try:
        otp_data_query = db.query(EmailOTPs).filter(EmailOTPs.email == otp_verify.email)
        otp_data = otp_data_query.first()
        
        if not otp_data or otp_data.otp != otp_verify.otp or otp_data.expires_at < datetime.now():
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")
        
        otp_data_query.delete(synchronize_session=False)
        db.commit()

        # Update the user's record with the generated access token
        user = db.query(User).filter(User.email == otp_verify.email).first()
        if user:
            # Collect all role IDs of the user
            role_ids = [role.id for role in user.roles]
            data = {"user_id": user.uuid,"email": user.email, "phone_number": user.phone_number, "role_ids": role_ids}
            access_token = generate_token(data=data)
            # refresh token 
            refresh_token = generate_refresh_token(data=data)
            user.access_token = access_token
            db.commit()
            # Set the refresh token in a secure HTTP-only cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,        # Prevents access to the cookie via JavaScript
                secure=False,          # Ensures the cookie is only sent over HTTPS
                # samesite="strict",    # Helps mitigate CSRF attacks
                max_age=3 * 24 * 60 * 60  # 1 week expiration for refresh token
            )
            return {"access_token": access_token, "token_type": "bearer","uuid": user.uuid,"role_ids":role_ids}
        else:
            raise HTTPException(status_code=404, detail="User not found!")
    except HTTPException as e:
        logger.warning(f"HTTP error: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"Error during OTP verification: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to verify OTP")

# Send the OTP to the user's phone number
@router.post("/request-otp-phone")
async def request_otp(otp_request: OTPRequest, db: Session = Depends(get_db)):
    # Check if the phone number exists in the User table
    user = db.query(User).filter(User.phone_number == otp_request.phone_number).first()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "User does not exist.",
                "results": None,
                "errors": "Phone number not found in the system."
            }
        )

    # Send OTP using the send_otp function
    otp_status = send_otp(otp_request.phone_number)

    if otp_status == "pending":  # Assuming "pending" indicates the OTP was sent successfully
        return {
            "message": "OTP sent successfully.",
            "results": "",
            "status": 200,
            "errors": ""
        }
    else:
        logger.error(f"Failed to send OTP, status: {otp_status}")
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Failed to send OTP.",
                "results": None,
                "errors": "An error occurred while sending OTP."
            }
        )

  # Verify the OTP sent to the user's phone number  
@router.post("/verify-otp-phone")
async def verify_otp_phone(otp_verify: OTPVerify, response: JSONResponse, db: Session = Depends(get_db)):
    """Verify the OTP sent to the user's phone number."""

    # Use the verify_otp function to check the OTP
    verification_status = verify_otp_twilio(otp_verify.phone_number, otp_verify.otp)

    if verification_status != "approved":  # Assuming "approved" indicates successful verification
        raise HTTPException(
            status_code=400,
            detail={
                "message": "User does not exist.",
                "errors": "Phone number not found in the system."
            }
        )

    # if otp_verify.otp != "123456":
    #     return {"message": "Failed to verify OTP", "status": 400, "errors": "Invalid or expired OTP."}
    

    # Fetch user from the database based on phone number
    user = db.query(User).filter(User.phone_number == otp_verify.phone_number).first()
    
    if user:
        # Collect the user's role IDs (since a user can have multiple roles)
        role_ids = [role.id for role in user.roles]
    else:
        # If no user is found, default to role_id 1 (as per your logic)
        role_ids = [1]
    
    # Generate token using the phone number and user data
    data = {
        "user_id": user.uuid,  # Include user UUID if user exists
        "email": user.email,
        "phone_number": otp_verify.phone_number,
        "role_ids": role_ids  # Include list of role IDs
    }

    # Generate the access token
    access_token = generate_token(data=data)
    user.access_token = access_token
    db.commit()
    
    # Generate the refresh token
    refresh_token = generate_refresh_token(data=data)

    # Set the refresh token in a secure HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,        # Prevents access to the cookie via JavaScript
        secure=False,          # Ensures the cookie is only sent over HTTPS
        # samesite="strict",    # Helps mitigate CSRF attacks
        max_age=3 * 24 * 60 * 60  # 1 week expiration for refresh token
    )

    # Return access token and other information
    return {
        "message": "OTP verified successfully.",
        "results": {
            "access_token": access_token,
            "token_type": "bearer",
            "uuid": user.uuid,  # Include user UUID in the response
            "role_ids": role_ids
        },
        "status": 200,
        "errors": None
    }


@router.post("/request-otp-mobile") 
async def request_otp(otp_request: OTPRequest, db: Session = Depends(get_db)):
    """
    Handle OTP requests for both registered and unregistered phone numbers.
    """
    try:
        # Check if a static mobile number is provided
        phone_number = otp_request.phone_number if otp_request.phone_number else "+919999988888"

        if phone_number == "+919999988888":
            # For the static number, bypass the database check and sending OTP
            return {
                "message": f"OTP sent successfully to number {phone_number}.",
                "results": None,
                "status": 200,
                "errors": None
            }

        # Check if the phone number exists in the User table
        user = db.query(User).filter(User.phone_number == phone_number).first()

        # Send OTP
        otp_status = send_otp(phone_number)

        if otp_status == "pending":  # Assuming "pending" indicates OTP was sent successfully
            message = (
                "OTP sent successfully." if user
                else f"OTP sent successfully to number {phone_number}."
            )
            return {
                "message": message,
                "results": None,
                "status": 200,
                "errors": None
            }
        else:
            # Log the failure and raise an HTTPException
            logger.error(
                f"Failed to send OTP{' to unregistered number' if not user else ''}, status: {otp_status}"
            )
            raise HTTPException(
                status_code=500,
                detail="An error occurred while sending OTP."
            )
        # return {
        #     "message": "OTP sent successfully.",
        #     "results": None,
        #     "status": 200,
        #     "errors": None
        # }

    except Exception as e:
        # Log the error and raise an HTTPException
        logger.error(f"Failed to send OTP: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while sending OTP."
        )

@router.post("/verify-otp-mobile")
async def verify_otp_phone(otp_verify: OTPVerify, response: JSONResponse, db: Session = Depends(get_db)):
    """
    Verify the OTP for a phone number and return user-related data or default values if the user is not in the database.
    """
    try:
        #  For the static number, bypass OTP verification and database checks
        
        # Use static OTP and phone number if provided, otherwise default to input values
        phone_number = otp_verify.phone_number if otp_verify.phone_number else "+919999988888"
        otp = otp_verify.otp if otp_verify.otp else "123456"

        if phone_number == "+919999988888":
            # For the static number, bypass OTP verification and database checks
            if otp != "123456":
                raise HTTPException(
                    status_code=400,
                    detail="Invalid or expired OTP for static number."
                )

            return {
                "message": "OTP verified successfully for static number.",
                "results": {
                    "access_token": None,
                    "token_type": None,
                    "uuid": None,
                    "role_ids": [2]  # Default role ID
                },
                "status": 200,
                "errors": None
            }

        # Step 1: Verify OTP
        verification_status = verify_otp_twilio(phone_number, otp)
        if verification_status != "approved":  # Assuming "approved" indicates successful verification
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired OTP."
            )

        # Step 2: Check user in the database
        user = db.query(User).filter(User.phone_number == otp_verify.phone_number).first()

        if user:
            # Existing user: Collect role IDs
            role_ids = [role.id for role in user.roles]  # Assuming a user can have multiple roles

            # Step 3: Generate access token
            data = {
                "user_id": user.uuid,  # Include user UUID
                "email": user.email,
                "phone_number": otp_verify.phone_number,
                "role_ids": role_ids
            }
            access_token = generate_token(data=data)

            # Update user access token in the database
            user.access_token = access_token
            db.commit()

            # Step 4: Generate refresh token
            refresh_token = generate_refresh_token(data=data)

            # Step 5: Set refresh token in a secure HTTP-only cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=False,  # Change to True in production
                max_age=3 * 24 * 60 * 60  # 3 days expiration
            )
        else:
            # User not found: Default role ID and null tokens
            role_ids = [2]  # Default role ID
            access_token = None
            refresh_token = None

        # Step 6: Return response
        return {
            "message": "OTP verified successfully.",
            "results": {
                "access_token": access_token,
                "token_type": "bearer" if access_token else None,
                "uuid": user.uuid if user else None,  # Include user UUID if user exists
                "role_ids": role_ids
            },
            "status": 200,
            "errors": None
        }

    except HTTPException as http_exc:
        # Catch and raise HTTP exceptions
        raise http_exc
    except Exception as e:
        # Log unexpected errors and raise a generic HTTP exception
        logger.error(f"Failed to verify OTP: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred during OTP verification."
        )
 
 # this API is used to reset the password
@router.post("/reset-password")
async def reset_password(password_reset: PasswordReset, db: Session = Depends(get_db)):
    user_query = db.query(User).filter(User.email == password_reset.email)
    user = user_query.first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    new_password = password_reset.new_password
    hashed_new_password = get_password_hash(new_password)
    current_hashed_password = user.hashed_password
    if not verify_password(password_reset.current_password, current_hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password.")
    if verify_password(new_password, current_hashed_password):
        raise HTTPException(status_code=400, detail="New password cannot be the same as the current")
    
    user_query.update({"hashed_password": hashed_new_password})
    db.commit()

    return {"msg": "Password reset successfully"}


# This API is validate the access token and return the user data
@router.post("/token")
async def verify_token(token: str, db: Session = Depends(get_db)):
    # Validate the token and get the user
    user = await get_current_user(token, db)
    print(user)
    
    # Check if the user's stored access token matches the provided one
    if user.access_token != token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Ensure the user exists and their UUID matches the token's user ID
    if user :
        # Convert user roles into dictionaries
        role_responses = [
            {
                "id": role.id,
                "role_name": role.role_name,
                "permissions": role.permissions,  # Assuming role.permissions is a List[Dict]
                "department_name": role.department_name,
                "department_id": role.department_id
            }
            for role in user.roles
        ]

        # Create the user response dictionary
        user_response = {
            "uuid": user.uuid,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "email": user.email,
            "phone_number": user.phone_number,
            "roles": role_responses,
            "status": user.status
        }

        # Return the user data as a JSON response
        return {
            "results": user_response
        }

    # If the token is invalid or no matching role is found, return unauthorized
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# This API is used to refresh token to generate new access token
@router.post("/refresh-token")
async def refresh_access_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        # Decode the refresh token to get the user data
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")  # Now a UUID (str)
        email = payload.get("email")
        phone_number = payload.get("phone_number")
        role_ids = payload.get("role_ids")  # Assuming roles are a list of IDs
        expiry_time = payload.get("exp")

        # Check if the refresh token has expired
        if isinstance(expiry_time, int):
            expiry_time = datetime.fromtimestamp(expiry_time)
            if expiry_time < datetime.now():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has expired",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
        if not phone_number or not role_ids or not user_id or not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"}
            )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Query the user to ensure the token data matches the actual user
    user = db.query(User).filter(User.uuid == user_id).first()
    # Generate a new access token
    data = {
        "user_id": user.uuid,  # Convert UUID to string if needed
        "email": user.email,
        "phone_number": phone_number,
        "role_ids": [role.id for role in user.roles]  # Update role_ids as a list
    }
    access_token = generate_token(data=data)
    user.access_token = access_token
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# Send email to reset the password
@router.post("/forget-password")
async def forget_password(password_forget: PasswordForget, db: Session = Depends(get_db)):
    try:
        # Fetch the user based on the email provided
        user = db.query(User).filter(User.email == password_forget.email).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        role_ids = [role.id for role in user.roles]
        
        # Generate an access token for the user
        data = {"user_id": user.uuid,"email": user.email, "phone_number": user.phone_number, "role_ids": role_ids}
        access_token = generate_token(data=data)
        
        # Update the user's access token
        user.access_token = access_token
        db.commit()
        # Base_url = password_forget.base_url
        # Create a URL for resetting the password
        url = f"{password_forget.base_url}/auth/reset-forget-password/{access_token}"
        
        # Send an email with the reset link
        email_response = await send_email(password_forget.email, url)
        return {"detail": email_response}
    
    except HTTPException as http_err:
        logger.error(f"HTTPException occurred: {str(http_err)}\n{traceback.format_exc()}")
        raise http_err
    except Exception as e:
        logger.error(f"Error in forget_password: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


# Reset the password using the token
@router.post("/reset-forget-password/{token}")
async def reset_forget_password(token: str, new_passwords: SetNewPassword, db: Session = Depends(get_db)):

    # Validate the token and get the user
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    if user.access_token != token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    new_password = new_passwords.new_password
    confirm_password = new_passwords.confirm_password
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm Password should be same do not match")
    hashed_new_password = get_password_hash(new_password)
    user_query = db.query(User).filter(User.email == user.email)
    user_query.update({"hashed_password": hashed_new_password})
    db.commit()
    return {"msg": "Password reset successfully."}

# this is the API to create a new user return only the message
@router.post("/create-user")
async def create_user(user: UserSchema, db: Session = Depends(get_db)):
    # Check if the user already exists by email
    existing_user = db.query(User).filter(User.email == user.email).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash the user's password
    hashed_password = get_password_hash(user.password)
    
    # Assign role(s) based on provided role_id(s); default to role_id 1 if not provided
    if hasattr(user, 'role_ids') and user.role_ids:
        role_ids = user.role_ids
    else:
        role_ids = [1]  # Default to role_id 1
    
    # Fetch the roles based on the provided role_ids
    roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
    
    # Create a new user and assign the roles
    db_user = User(
        firstname=user.firstname,
        lastname=user.lastname,
        email=user.email,
        phone_number=user.phone_number,
        hashed_password=hashed_password,
        roles=roles  # Assign roles to the user
    )
    
    # Add and commit the new user
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    # # Call the SCHEDULAR API after user creation
    send_user_data_to_SCHEDULAR_API(db_user.uuid, db_user.firstname, db_user.lastname, [role.id for role in db_user.roles])
    create_calendar(db_user.uuid)
    
    return {"msg": "User registered successfully"}

# get the user by id
@router.post("/get-userbyid/{user_id}", response_model=CustomResponse)
async def get_user_by_id(user_id: str, db: Session = Depends(get_db)):
    # Ensure the provided user_id is in the correct format (24-character hexadecimal)
    if len(user_id) != 24 or not all(c in '0123456789abcdef' for c in user_id):
        return CustomResponse(
            message="Invalid UUID format.",
            results=None,
            status=400,
            errors="Provided ID is not a valid custom UUID."
        )

    # Query the user from the database using the string uuid
    user = db.query(User).filter(User.uuid == user_id).first()

    # If user not found, return a 404 response
    if not user:
        return CustomResponse(
            message="User not found.",
            results=None,
            status=404,
            errors="User with the provided UUID does not exist."
        )

    # Convert user roles into RoleResponse objects
    role_responses = [
        RoleResponse(
            id=role.id,
            role_name=role.role_name,
            permissions=role.permissions,  # Assuming role.permissions is a List[Dict]
            department_name=role.department_name,  
            department_id=role.department_id  
        )
        for role in user.roles
    ]

    # Create the user response object
    user_response = UserResponse(
        uuid=user.uuid,
        firstname=user.firstname,
        lastname=user.lastname,
        email=user.email,
        phone_number=user.phone_number,
        role_ids=role_responses,  # Return RoleResponse objects instead of just role IDs
        source_profile=user.source_profile,
        status=user.status
    )

    # Return the user data
    return CustomResponse(
        message="User fetched successfully.",
        results=[user_response],
        status=200,
        errors=None
    )

# get all the users
@router.post("/users", response_model=CustomResponse)
async def get_all_users(db: Session = Depends(get_db)):
    # Query all users from the database
    users = db.query(User).all()

    # If no users are found, return a custom error response
    if not users:
        return CustomResponse(
            message="No users found.",
            results=None,
            status=404,
            errors="The database contains no users."
        )

    # Prepare the list of user responses
    user_responses = [
        UserResponse(
            uuid=user.uuid,
            firstname=user.firstname,
            lastname=user.lastname,
            email=user.email,
            phone_number=user.phone_number,
            role_ids=[
                RoleResponse(
                    id=role.id,
                    role_name=role.role_name,
                    permissions=role.permissions,  # Assuming role.permissions is a List[Dict]
                    department_name=role.department_name,  # Directly using the department_name column from Role table
                    department_id=role.department_id  # Directly using the department_id column from Role table
                ) for role in user.roles  # Access each user's roles
            ],
            source_profile=user.source_profile,
            status=user.status
        )
        for user in users
    ]

    # Return the list of users
    return CustomResponse(
        message="Users fetched successfully.",
        results=user_responses,
        status=200,
        errors=None
    )


# Update the user details by id
@router.post("/update/{user_id}", response_model=UserUpdateSchema)
async def update_user(
    user_id: str,
    user_update: UserUpdateSchema,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.uuid == user_id).first()
    
    # If user not found, raise a 404 error
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Ensure the current user is the one being updated or has proper authorization
    if user.uuid != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
    
    # Update user details
    update_data = user_update.model_dump(exclude_unset=True)
    
    # Validate status
    if 'status' in update_data and update_data['status'] not in [0, 1]:
        raise HTTPException(status_code=400, detail="Invalid status value. Must be 0 or 1.")
    
    # Update the user's roles
    if 'role_ids' in update_data:
        # Retrieve the roles from the database
        new_roles = db.query(Role).filter(Role.id.in_(update_data['role_ids'])).all()
        if len(new_roles) != len(update_data['role_ids']):
            raise HTTPException(status_code=400, detail="Some roles do not exist.")
        # Update the user's roles
        user.roles = new_roles
    
    # Update other user attributes
    for key, value in update_data.items():
        if key != 'role_ids' and value is not None:  # Skip role_ids since it was already handled
            setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    
    return user


# get all the roles that active
@router.post("/roles", response_model=CustomRoleResponse)
async def get_all_roles(db: Session = Depends(get_db)):
    # Query all roles from the database
    # roles = db.query(Role).all()
    # Query only active roles from the database
    roles = db.query(Role).filter(Role.is_active == True).all()

    # If no roles are found, raise a custom error response
    if not roles:
        return {
            "message": "No roles found.",
            "results": None,
            "status": 404,
            "errors": "The database contains no roles."
        }

    # Return the list of roles in the desired format
    return {
        "message": "Roles fetched successfully.",
        "results": roles,
        "status": 200,
        "errors": None
    }

# create a new role
@router.post("/create_roles", response_model=List[RoleResponseSchema])
async def create_roles(roles: List[RoleCreateSchema], db: Session = Depends(get_db)):
    """
    Create multiple roles at a time with optional department details.
    """
    new_roles = []
    for role in roles:
        if role.role_id:  # Check if role_id is provided
            new_role = Role(
                id=role.role_id, 
                role_name=role.role_name, 
                permissions=role.permissions,
                department_name=role.department_name,  # Set department name
                department_id=role.department_id       # Set department ID
            )
        else:
            new_role = Role(
                role_name=role.role_name, 
                permissions=role.permissions,
                department_name=role.department_name,  # Set department name
                department_id=role.department_id       # Set department ID
            )

        db.add(new_role)
        new_roles.append(new_role)
    db.commit()  # Commit the transaction once after all roles are added

    # # Refresh each new role to retrieve its ID and other generated values
    for new_role in new_roles:
        db.refresh(new_role)
        if new_role.id:  # Ensure role_id is available
            send_role_data_to_SCHEDULAR_API(new_role.id, new_role.role_name)  # Send data to SCHEDULAR API
    return new_roles


# Update the role details by id
@router.post("/roles/{role_id}/update", response_model=RoleResponseSchema)
async def update_role_details(
    role_id: int,
    role_update: RoleUpdateSchema,
    db: Session = Depends(get_db)
):
    # Fetch the role by ID
    role = db.query(Role).filter(Role.id == role_id).first()

    # If role not found, raise a 404 error
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    # Update role_name, department_name, and department_id if provided
    if role_update.role_name is not None:
        role.role_name = role_update.role_name
    if role_update.department_name is not None:
        role.department_name = role_update.department_name
    if role_update.department_id is not None:
        role.department_id = role_update.department_id

    # Commit the changes to the database
    db.commit()
    db.refresh(role)
    return role

# Update the role permissions by id
@router.post("/roles/update_permissions", response_model=List[RoleResponseSchema])
async def update_multiple_permissions(
    permission_updates: List[PermissionsUpdateSchema],
    db: Session = Depends(get_db)
):
    updated_roles = []
    for permission_update in permission_updates:
        # Fetch the role by ID
        role = db.query(Role).filter(Role.id == permission_update.role_id).first()

        # If role not found, raise a 404 error
        if not role:
            raise HTTPException(status_code=404, detail=f"Role with ID {permission_update.role_id} not found")

        # Update permissions for the role
        # Assuming permission_update.permissions is a list of dictionaries
        role.permissions = permission_update.permissions

        # Commit the changes to the database
        db.commit()
        db.refresh(role)
        updated_roles.append(role)
    return updated_roles

# Update the role status by id
@router.post("/roles/{role_id}/update_status", response_model=RoleResponseSchema)
async def update_role_status(
    role_id: int,
    is_active: bool = None,
    db: Session = Depends(get_db)
):
    # Fetch the role by ID
    role = db.query(Role).filter(Role.id == role_id).first()

    # If role not found, raise a 404 error
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    # Update the status (is_active and is_archived)
    # Update the status based on provided parameters
    if is_active is not None:
        role.is_active = is_active
    # role.is_archived = status_update.is_archived
    # Ensure that permissions is a list (not None)
    if role.permissions is None:
        role.permissions = []
    # Commit the changes to the database
    db.commit()
    db.refresh(role)
    return role


# add user API to create or update the user details 
@router.post("/add_user")
def create_or_update_user(user_data: AddUser, db: Session = Depends(get_db)):
    
    # Check if the user already exists based on phone number
    existing_user = db.query(User).filter(User.phone_number == user_data.phone_number).first()
    # Assign role(s); default to role_id 1 if not provided
    role_ids = user_data.role_ids if user_data.role_ids else [1]
    roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
    if not roles:
        raise HTTPException(status_code=400, detail="No valid roles found for the user.")
    
    # Hash the password if it matches the phone number
    if user_data.phone_number == user_data.hashed_password:
        user_data.hashed_password = get_password_hash(user_data.hashed_password)

    if existing_user:
        # Check if the new email already exists in the database
        if user_data.email and user_data.email != existing_user.email:
            email_exists = db.query(User).filter(User.email == user_data.email).first()
            if email_exists:
                raise HTTPException(status_code=400, detail="Email already exists.")

    if existing_user:
        # Update existing user details
        existing_user.firstname = user_data.firstname or existing_user.firstname
        existing_user.lastname = user_data.lastname or existing_user.lastname
        existing_user.email = user_data.email or existing_user.email
        existing_user.phone_number = user_data.phone_number or existing_user.phone_number
        existing_user.hashed_password = user_data.hashed_password or existing_user.hashed_password
        existing_user.status = user_data.status if user_data.status is not None else existing_user.status

        # Append new roles if not already assigned
        existing_role_ids = {role.id for role in existing_user.roles}
        new_roles = [role for role in roles if role.id not in existing_role_ids]
        existing_user.roles.extend(new_roles)
    else:
        # Create a new user if not exists
        new_user = User(
            uuid=user_data.uuid,
            firstname=user_data.firstname,
            lastname=user_data.lastname,
            email=user_data.email,
            phone_number=user_data.phone_number,
            hashed_password=user_data.hashed_password,
            status=user_data.status or 1,
            roles=roles
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
         # Call the SCHEDULAR API after user creation
        send_user_data_to_SCHEDULAR_API(new_user.uuid, new_user.firstname,new_user.lastname,[role.id for role in new_user.roles])
        create_calendar(new_user.uuid)

        return {"message": "User created successfully", "roles": [role.id for role in new_user.roles], "user_id": new_user.email, "uuid": new_user.uuid}

    db.commit()
    db.refresh(existing_user)
    return {"message": "User updated successfully", "roles": [role.id for role in existing_user.roles], "user_id": existing_user.email, "uuid": existing_user.uuid}


bucket_name = os.getenv("S3_BUCKET_NAME")

@router.post("/upload-image", status_code=201)
async def upload_image(file: UploadFile = File(...)):
    """
    API to upload an image to S3 and return its public URL.
    """
    try:
        # Validate file extension
        extension = file.filename.split(".")[-1]
        if extension.lower() not in {"jpg", "jpeg", "png", "gif", "webp", "avif"}:
            raise HTTPException(status_code=400, detail="Unsupported file type")

        # Generate unique file name
        file_name = f"{uuid.uuid4()}.{extension}"

        # Upload the file to S3
        image_url = upload_file_to_s3(file, S3_BUCKET_NAME, file_name)
        return {"message": "Image uploaded successfully", "image_url": image_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Delete the user by id or phone number
@router.delete("/delete-user", response_model=CustomResponse)
async def delete_user(
    uuid: Optional[str] = None,
    mobile_number: Optional[str] = None,
    db: Session = Depends(get_db)
):
    # Ensure at least one identifier is provided
    if not uuid and not mobile_number:
        return CustomResponse(
            message="Either UUID or mobile number must be provided.",
            results=None,
            status=400,
            errors="No identifier provided."
        )

    # Validate UUID format if provided
    if uuid and (len(uuid) != 24 or not all(c in '0123456789abcdef' for c in uuid)):
        return CustomResponse(
            message="Invalid UUID format.",
            results=None,
            status=400,
            errors="Provided UUID is not valid."
        )

    # Query user based on UUID or mobile number
    user_query = db.query(User)
    if uuid:
        user_query = user_query.filter(User.uuid == uuid)
    elif mobile_number:
        user_query = user_query.filter(User.phone_number == mobile_number)

    user = user_query.first()

    # If user not found, return a 404 response
    if not user:
        return CustomResponse(
            message="User not found.",
            results=None,
            status=404,
            errors="No user found with the provided identifier."
        )

    # Delete the user
    db.delete(user)
    db.commit()

    # Return success response
    return CustomResponse(
        message="User deleted successfully.",
        results=None,
        status=200,
        errors=None
    )

# Get user IDs by role
@router.post("/users/by-role", response_model=CustomuserResponse)
async def get_user_ids_by_role(role_id: int, db: Session = Depends(get_db)):
    # Query users filtered by the role ID
    users = db.query(User).join(User.roles).filter( Role.id == role_id).all()


    # If no users are found, return a custom error response
    if not users:
        return CustomuserResponse(
            message="No users found for the given role.",
            results=None,
            status=404,
            errors=f"No users with role_id {role_id}."
        )

    # Extract user IDs
    user_ids = [user.uuid for user in users]

    # Return the list of user IDs
    return CustomuserResponse(
        message="User IDs fetched successfully.",
        results=UserIDsResponse(user_ids=user_ids),
        status=200,
        errors=None
    )

# Get user by phone number
@router.post("/get_user/{phone_number}")
def get_user_by_phone(phone_number: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone_number == phone_number).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"uuid": user.uuid, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "phone_number": user.phone_number, "roles": [role.id for role in user.roles]}

