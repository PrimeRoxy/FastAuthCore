# Authentication API with FastAPI

This repository contains a FastAPI-based authentication and authorization microservice designed to serve multiple web and mobile applications from a centralized system. It provides a scalable solution for user authentication, authorization control, and role-based access management.

This microservice ensures that all applications within the ecosystem, whether web or mobile, have seamless access to authentication and authorization functions from a single source. It offers endpoints for :

- **User Management:**  
  - Sign up, sign in, and update user details  
  - Retrieve individual or all user profiles  
  - Delete users by UUID or phone number

- **OTP Verification:**  
  - Request and verify OTP via email and phone  
  - Supports mobile OTP requests with static bypass for testing

- **Token Management:**  
  - Generate JSON Web Tokens (JWT) for access and refresh  
  - Validate tokens and refresh expired access tokens

- **Password Management:**  
  - Reset password for authenticated users  
  - Forgot password flow with email reset links

- **Role-Based Access Control (RBAC):**  
  - Assign, update, and manage user roles across applications  
  - Control access to endpoints based on role permissions

- **Multi-App & Multi-User Authorization:**  
  - Supports different applications (web, mobile) with unified authentication  
  - Centralized role management for all connected services

- **Image Upload:**  
  - Upload images to an AWS S3 bucket

This microservice enables organizations to manage user authentication and authorization seamlessly across various applications, ensuring security, scalability, and ease of integration.


## Getting Started

### Prerequisites

- **Python 3.8+**
- [FastAPI](https://fastapi.tiangolo.com/)
- [Uvicorn](https://www.uvicorn.org/) or any other ASGI server
- A supported SQL database (e.g., PostgreSQL) configured with SQLAlchemy
- AWS S3 account (for image uploads)
- Environment variables configured as described below

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/PrimeRoxy/FastAuthCore.git
   cd FastAuthCore
   ```

2. **Create and Activate a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Environment Variables

Create a `.env` file in the root directory and set the following variables:

```
SSO_KALEYRA_API_KEY=your_kaleyra_api_key
SSO_KALEYRA_SID=your_kaleyra_sid
SENDER_ID=your_sender_id
TEMPLATE_ID=your_template_id
MESSAGE_TEMPLATE=your_message_template
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=2
SECRET_KEY=your_secret_key
ALGORITHM=HS256
DATABASE_URL=postgresql://username:password@localhost/dbname

OTP_EXPIRATION_TIME=10
ROLES=Visitors,Guest,User,Admin,
SMTP_USER =''
SMTP_PASSWORD=''
SMTP_PORT ='587'
BASE_URL = 'http://127.0.0.1:8000/'
EMAIL_TEMPLATE="<html><body><h2>Password Reset Request</h2><p>It seems like you forgot your password. Click the link below to set a new one:</p><p><a href='{set_new_password_link}'>Set Your New Password</a></p><p>If you did not request this, please ignore this email.</p></body></html>"
OTP_EMAIL_TEMPLATE='<html><body><h2>Your OTP Code</h2><p>Your one-time password (OTP) is: <strong>{otp}</strong></p><p>This OTP is valid for 10 minutes.</p><p>If you did not request this code, please ignore this email.</p></body></html>'

TWILIO_ACCOUNT_SID = ''
TWILIO_AUTH_TOKEN = ''
TWILIO_SERVICE_ID = ''

SCHEDULAR_API = ''
EMAIL_API = ''

AWS_S3_BUCKET=
S3_REGION=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=



```

Adjust the values according to your configuration.

### Running the Application

Run the FastAPI application using Uvicorn:

```bash
uvicorn main:app --reload
```

## API Endpoints

### Authentication & User Endpoints

- **POST `/signup`**  
  Register a new user and generate access & refresh tokens.

- **POST `/signin`**  
  Authenticate an existing user using email and password.

- **POST `/token`**  
  Validate an access token and retrieve the corresponding user details.

- **POST `/refresh-token`**  
  Generate a new access token using a valid refresh token.

- **POST `/forget-password`**  
  Send a password reset link to the user’s email.

- **POST `/reset-password`**  
  Reset the password for an authenticated user.

- **POST `/reset-forget-password/{token}`**  
  Reset the password using a token from the forget password flow.

- **POST `/get-userbyid/{user_id}`**  
  Retrieve a user’s details using their UUID.

- **POST `/users`**  
  Fetch all users from the database.

- **POST `/update/{user_id}`**  
  Update the details of an existing user.

### OTP Endpoints

- **POST `/request-otp`**  
  Send an OTP to the user’s email.

- **POST `/verify-otp`**  
  Verify the OTP sent to the user’s email.

- **POST `/request-otp-phone`**  
  Request an OTP to be sent to the user’s phone.

- **POST `/verify-otp-phone`**  
  Verify the OTP sent to the user’s phone.

- **POST `/request-otp-mobile`**  
  Request an OTP for mobile verification (includes static number bypass for testing).

- **POST `/verify-otp-mobile`**  
  Verify the OTP for mobile (supports static bypass).

### Role & Permission Endpoints

- **POST `/roles`**  
  Retrieve all active roles.

- **POST `/create_roles`**  
  Create one or multiple new roles.

- **POST `/roles/{role_id}/update`**  
  Update the details of a specific role.

- **POST `/roles/update_permissions`**  
  Update permissions for multiple roles.

- **POST `/roles/{role_id}/update_status`**  
  Update the active status of a role.

### Additional Endpoints

- **POST `/create-user`**  
  Create a user and return a success message.

- **POST `/add_user`**  
  Create or update user details.

- **POST `/upload-image`**  
  Upload an image to an S3 bucket and receive its public URL.

- **DELETE `/delete-user`**  
  Delete a user by UUID or mobile number.

- **POST `/users/by-role`**  
  Retrieve user IDs filtered by a specific role.

- **POST `/get_user/{phone_number}`**  
  Retrieve user details using their phone number.

For more detailed documentation, refer to the inline comments within the source code in `auth.py`.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your proposed changes. For major changes, open an issue first to discuss what you would like to change.


## Contact

For questions or support, please open an issue or contact [vipuldashingboy@gmail.com](mailto:vipuldashingboy@gmail.com).
