from pydantic import BaseModel, EmailStr
from typing import List,Dict, Optional

class UserSchema(BaseModel):
    firstname: str
    lastname: str
    email: EmailStr
    phone_number: str
    password: str
    role_ids: Optional[List[int]] = [1]  # Default to role_id 1 if not provided
    source_profile: Optional[str] = None  # Optional image URL or file path

class UserSignInSchema(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    role_ids: List[int]
    user_id: str
    # token_type: str

class OTPRequest(BaseModel):
    phone_number: str


class OTPVerify(BaseModel):
    phone_number: str
    otp: str

class PasswordReset(BaseModel):
    email: str
    current_password: str
    new_password: str

class PasswordForget(BaseModel):
    email : str
    base_url: str

class EmailOtp(BaseModel):
    email : str

class EmailOTPVerify(BaseModel):
    email : str
    otp: str

class SetNewPassword(BaseModel):
    new_password: str
    confirm_password: str

class UserUpdateSchema(BaseModel):
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    role_ids: Optional[List[int]] = [1]
    source_profile: Optional[str] = None
    status: Optional[int] = 1

# class GetUser(BaseModel):
#     User_id: int

# Function to convert ObjectId to string
def str_object_id(obj_id):
    return str(obj_id) if obj_id else None

class RoleResponse(BaseModel):
    id: int
    role_name: str
    permissions: Optional[List[Dict[str, int]]]
    department_name: Optional[str] = None  # Optional field
    department_id: Optional[str] = None
    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    uuid: str
    firstname: str
    lastname: str
    email: str
    phone_number: str
    role_ids: List[RoleResponse]  
    # role_ids: List[int]
    source_profile: Optional[str] = None  # Ensure this is optional
    status: int

    class Config:
        from_attributes = True

class CustomResponse(BaseModel):
    message: str
    results: Optional[List[UserResponse]] = None
    status: int
    errors: Optional[str] = None

class CustomRoleResponse(BaseModel):
    message: str
    results: Optional[List[RoleResponse]] = None
    status: int
    errors: Optional[str] = None

class AccessToken(BaseModel):
    access_token: str


class PermissionUpdateSchema(BaseModel):
    permissions: List[Dict[str, int]]

    class Config:
        from_attributes = True

class PermissionsUpdateSchema(BaseModel):
    role_id: int
    permissions: List[Dict[str, int]]

    class Config:
        from_attributes = True


class RoleResponseSchema(BaseModel):
    id: int
    role_name: str
    permissions: List[Dict[str, int]]
    department_name: Optional[str] = None  # Optional field
    department_id: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True  # Allows Pydantic to work with SQLAlchemy ORM objects

class RoleCreateSchema(BaseModel):
    role_id: Optional[int] = None
    role_name: str
    permissions: Optional[List[Dict[str, int]]]
    department_name: Optional[str] = None  # Optional field
    department_id: Optional[str] = None
    

class RoleStatusUpdateSchema(BaseModel):
    is_active: bool



class AddUser(BaseModel):
    uuid: Optional[str] = None
    firstname: str
    lastname: str
    email: str
    phone_number: str
    hashed_password: str
    role_ids: Optional[List[int]] = []  # Default to an empty list
    status: Optional[int] = 1  # Default status is 1 (Active)

    class Config:
        from_attributes = True

class VisitorResponse(BaseModel):
    uuid: str
    firstname: str
    lastname: str
    email: str
    phone_number: str
    status: int

    class Config:
        from_attributes = True

class CustomVisitorResponse(BaseModel):
    message: str
    count: Optional[int] = None  # Add count to store the visitor count
    results: Optional[List[VisitorResponse]] = None
    status: int
    errors: Optional[str] = None

class RoleUpdateSchema(BaseModel):
    role_name: Optional[str] = None
    department_name: Optional[str] = None
    department_id: Optional[str] = None

    class Config:
        from_attributes = True


class UserIDsResponse(BaseModel):
    user_ids: List[str]

class CustomuserResponse(BaseModel):
    message: str
    results: UserIDsResponse | None
    status: int
    errors: Optional[str] = None
