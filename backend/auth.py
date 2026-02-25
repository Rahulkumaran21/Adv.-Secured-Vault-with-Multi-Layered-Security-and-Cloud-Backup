# Login (Key + Password) logic
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from passlib.context import CryptContext
from Crypto.Random import get_random_bytes
import hashlib
import os
from app.services.email_service import send_private_key

router = APIRouter()

# Setup Password Hashing (Bcrypt is industry standard)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Temporary In-Memory Database (We will replace with SQLite later)
# Structure: { "user_email": { "pass_hash": "...", "key_hash": "...", "recovery_q": "..." } }
fake_users_db = {}

# --- Data Models ---
class IdentityCheck(BaseModel):
    email: str
    security_answer: str


class VaultCreate(BaseModel):
    email: str
    password: str
    security_question: str
    security_answer: str

class VaultLogin(BaseModel):
    email: str
    password: str
    private_key: str

# --- Helper Functions ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_key(private_key_hex):
    # We hash the key before storing it, so even the DB admin can't see the real key
    return hashlib.sha256(private_key_hex.encode()).hexdigest()

# --- Routes ---

@router.post("/create-vault")
def create_vault(data: VaultCreate):
    print(f"🔥 CREATE VAULT REQUEST RECEIVED FOR: {data.email}")
    if data.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Vault already exists for this email")

    # 1. Generate the Unique Private Key (The "Master Key")
    # We create a 64-character hex string (256 bits of entropy)
    raw_key_bytes = get_random_bytes(32)
    private_key_hex = raw_key_bytes.hex()

    # 2. Securely Hash Credentials
    password_hash = get_password_hash(data.password)
    answer_hash = get_password_hash(data.security_answer) # Hash the recovery answer too!
    key_hash = hash_key(private_key_hex) # Store only the hash of the key

    # 3. Save User (Simulated DB)
    fake_users_db[data.email] = {
        "pass_hash": password_hash,
        "key_hash": key_hash,
        "question": data.security_question,
        "answer_hash": answer_hash
    }

    print(f"DEBUG: Vault Created for {data.email}")
    print(f"DEBUG: Vault Created for {data.email}")
    
    # Send Email
    send_private_key(data.email, private_key_hex) # <--- Add this line

    
    
    # 4. Return the Private Key to user (Only time they will see it!)
    return {
        "message": "Vault created successfully",
        "user_email": data.email,
        "YOUR_PRIVATE_KEY": private_key_hex,
        "warning": "SAVE THIS KEY. IF YOU LOSE IT, YOUR DATA IS GONE FOREVER."
    }

@router.post("/login-vault")
def login_vault(data: VaultLogin):
    user = fake_users_db.get(data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check Password
    if not verify_password(data.password, user["pass_hash"]):
        # Increment failed attempts
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        
        # CHANGED: Lock immediately if attempts reach 2
        if user["failed_attempts"] >= 2:
            raise HTTPException(status_code=403, detail="LOCKED:Identity Required")
            
        # CHANGED: Math for remaining attempts (2 - 1 = 1 left)
        raise HTTPException(status_code=401, detail=f"Incorrect Password. Attempts left: {2 - user['failed_attempts']}")

    # Verify Key
    input_key_hash = hash_key(data.private_key)
    if input_key_hash != user["key_hash"]:
        # Increment failed KEY attempts (separate counter)
        user["failed_key_attempts"] = user.get("failed_key_attempts", 0) + 1
        
        # Lock if key attempts reach 2
        if user["failed_key_attempts"] >= 2:
            raise HTTPException(status_code=403, detail="LOCKED:Identity Required")
        
        raise HTTPException(status_code=401, detail=f"Invalid Private Key. Attempts left: {2 - user['failed_key_attempts']}")

    # Reset ALL attempts on successful login
    user["failed_attempts"] = 0
    user["failed_key_attempts"] = 0

    return {"message": "Access Granted", "token": "fake-jwt-token-for-now"}

@router.post("/verify-identity")
def verify_identity(data: IdentityCheck):
    user = fake_users_db.get(data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify Security Answer
    if not verify_password(data.security_answer, user["answer_hash"]):
        # WRONG ANSWER -> TRIGGER DESTRUCTION
        # We return a specific status that the frontend sees to trigger the API call
        raise HTTPException(status_code=410, detail="DESTROY_VAULT")
    
    # Correct Answer -> Generate Temp Password & Invalidate Old Password
    temp_password = "TEMP-" + hashlib.sha256(os.urandom(10)).hexdigest()[:12].upper()
    
    # Replace old password hash with temp password hash (invalidates old password)
    user["pass_hash"] = get_password_hash(temp_password)
    
    # Reset all failed attempts
    user["failed_attempts"] = 0
    user["failed_key_attempts"] = 0
    
    # Send temp password via email
    from app.services.email_service import send_temp_password
    send_temp_password(data.email, temp_password)
    
    return {"message": "Identity Verified. Temporary password sent to your email.", "temp_password": temp_password}

