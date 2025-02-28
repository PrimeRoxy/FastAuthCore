from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from database import get_db
import auth
import os 
from utils import seed_roles

BASE_DOMAIN = os.getenv('BASE_DOMAIN', 'DOMAIN.com')

# Custom middleware for dynamic CORS handling
class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        origin = request.headers.get("origin")
        if origin and origin.endswith(f".{BASE_DOMAIN}"):
            response = await call_next(request)
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "*"
            return response
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # When the application starts
    db: Session = next(get_db())  # Get a session from the dependency
    seed_roles(db)  # Seed the roles
    yield  # Application runs here


app = FastAPI(lifespan=lifespan)  # Instantiate FastAPI app with lifespan
app.add_middleware(DynamicCORSMiddleware)

# Add additional standard CORS for specific origins like localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include auth router for your authentication endpoints
app.include_router(auth.router)