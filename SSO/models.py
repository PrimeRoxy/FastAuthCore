from sqlalchemy import ARRAY,Boolean,JSON,ForeignKey, Integer, Table, Column, String, DateTime
from database import Base
from sqlalchemy.orm import relationship
import uuid
import binascii
from sqlalchemy.dialects.postgresql import UUID

def generate_custom_uuid():
    # Generate a UUID and format it as a 24-character hexadecimal string
    return binascii.hexlify(uuid.uuid4().bytes).decode('utf-8')[:24]


# Association table for many-to-many relationship between User and Role
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(24), default=generate_custom_uuid, unique=True, nullable=False)  # Custom UUID field
    firstname = Column(String)
    lastname = Column(String)
    email = Column(String)
    phone_number = Column(String)
    hashed_password = Column(String)
    access_token = Column(String)
    # Optional field to store user profile image
    source_profile = Column(String, nullable=True)  # Optional image URL or file path

    # Store multiple role IDs as an array (if necessary)
    role_ids = Column(ARRAY(Integer), default=[1])  # Default to role_id 1
    status = Column(Integer, default=1)

    # Many-to-many relationship with Role through user_roles association table
    roles = relationship("Role", secondary=user_roles, back_populates="users")

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True,unique=True)
    role_name = Column(String)
    permissions = Column(JSON, nullable=True)  # Store permissions as JSON (key-value pairs)
    department_name = Column(String, nullable=True)  # Department name
    department_id = Column(String, nullable=True)  # Department ID

    is_active = Column(Boolean, default=True,nullable=False)
    
    # Many-to-many relationship with User through user_roles association table
    users = relationship("User", secondary=user_roles, back_populates="roles")
    def get_permissions_dict(self):
        return {perm['permission_name']: perm['permission_id'] for perm in self.permissions}


class EmailOTPs(Base):
    __tablename__ = "emailotps"
    
    email = Column(String, primary_key=True)
    otp = Column(String)
    expires_at = Column(DateTime)


#  Junction table for the many-to-many relationship
role_phone_association = Table(
    'role_phone_association',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roleidentifiers.id'), primary_key=True),
    Column('phone_id', Integer, ForeignKey('phonenumbers.id'), primary_key=True)
)

