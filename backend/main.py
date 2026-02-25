from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from app.services.encryption_service import generate_key, encrypt_data, decrypt_data
import os
import json
import io
import shutil
import time
import pyzipper  # For password-protected ZIP files
# ... (keep existing imports)
from app.services.email_service import send_recovery_token
from app.api import auth
# ... (existing imports)
from app.api.auth import fake_users_db # <--- IMPORT THE USER DATABASE

# ... (rest of your code)


# Initialize the App
app = FastAPI(title="Secure File Vault API")

# Allow Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])


# --- CONFIGURATION ---
STORAGE_DIR = "storage/live_vaults"
METADATA_FILE = "storage/metadata.json"
os.makedirs(STORAGE_DIR, exist_ok=True)
DESTROY_DIR = "storage/destroyed_vaults"
os.makedirs(DESTROY_DIR, exist_ok=True)

# --- HELPER: Metadata Manager (Persist Ownership) ---
def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return {}
    try:
        with open(METADATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_metadata(filename, owner_email):
    data = load_metadata()
    data[filename] = owner_email
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f)

def get_file_owner(filename):
    data = load_metadata()
    return data.get(filename)

# --- ROUTES ---

@app.get("/")
def read_root():
    return {"status": "online", "message": "Secure Vault System is Active 🛡️"}

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    password: str = Form(...),      # The Vault Key
    user_email: str = Form(...)     # <--- NEW: Who owns this?
):
    try:
        # 1. Read file
        file_bytes = await file.read()
        
        # 2. Encrypt
        key, salt = generate_key(password)
        encrypted_data, tag, iv = encrypt_data(file_bytes, key)
        
        # 3. Save to Disk
        final_blob = salt + iv + tag + encrypted_data
        
        # We append a timestamp or UUID in production, but simple filename for now
        safe_filename = f"{file.filename}.enc" 
        file_path = os.path.join(STORAGE_DIR, safe_filename)
        
        with open(file_path, "wb") as f:
            f.write(final_blob)

        # 4. Save Ownership Metadata
        save_metadata(safe_filename, user_email)
            
        return {
            "filename": safe_filename,
            "owner": user_email,
            "status": "encrypted"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/files")
def list_files(user_email: str = Query(...)): # <--- NEW: Require email to list
    files = []
    metadata = load_metadata()

    if os.path.exists(STORAGE_DIR):
        for filename in os.listdir(STORAGE_DIR):
            if filename.endswith(".enc"):
                # SECURITY CHECK: Does this file belong to the user?
                if metadata.get(filename) == user_email:
                    stats = os.stat(os.path.join(STORAGE_DIR, filename))
                    files.append({
                        "name": filename, 
                        "size": stats.st_size,
                        "created": stats.st_ctime
                    })
    return files

@app.post("/download")
async def download_file(
    filename: str = Body(...), 
    private_key: str = Body(...),
    user_email: str = Body(...) # <--- NEW: Verify identity
):
    file_path = os.path.join(STORAGE_DIR, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # SECURITY CHECK: Ownership
    owner = get_file_owner(filename)
    if owner != user_email:
        raise HTTPException(status_code=403, detail="ACCESS DENIED: You do not own this file.")

    # 1. Read Encrypted File
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
    except Exception:
        raise HTTPException(status_code=500, detail="Could not read file.")

    # 2. Extract Components
    try:
        salt = file_content[:16]
        iv = file_content[16:32]
        tag = file_content[32:48]
        ciphertext = file_content[48:]
    except IndexError:
        raise HTTPException(status_code=400, detail="File corrupted.")

    # 3. Decrypt
    try:
        clean_key = private_key.strip()
        key, _ = generate_key(clean_key, salt)
        decrypted_data = decrypt_data(ciphertext, tag, iv, key)

        if decrypted_data is None:
            raise ValueError("Decryption returned None")
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption Failed (Wrong Key).")

    # 4. Stream File
    original_name = filename.replace(".enc", "")
    return StreamingResponse(
        io.BytesIO(decrypted_data), 
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={original_name}"}
    )
@app.post("/destroy-vault")
def destroy_vault(
    user_email: str = Body(...),
    private_key: str = Body(...) 
):
    print(f"DEBUG: Starting vault destruction for {user_email}")
    metadata = load_metadata()
    files_moved = 0
    recovery_token = f"REC-{int(time.time())}-{auth.hash_key(private_key)[:8].upper()}"

    # 1. Create a Temp Folder for quarantine
    user_quarantine_dir = os.path.join(DESTROY_DIR, f"temp_{user_email}")
    os.makedirs(user_quarantine_dir, exist_ok=True)

    # 2. Move encrypted files to quarantine folder (keep .enc files as-is)
    for filename in list(metadata.keys()):
        if metadata[filename] == user_email:
            source_path = os.path.join(STORAGE_DIR, filename)
            if os.path.exists(source_path):
                dest_path = os.path.join(user_quarantine_dir, filename)
                shutil.move(source_path, dest_path)
                files_moved += 1
                print(f"DEBUG: Moved {filename} to quarantine")
            del metadata[filename]

    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f)

    print(f"DEBUG: Files moved: {files_moved}")

    # 3. Create password-protected ZIP with recovery_token as password
    try:
        print("DEBUG: Creating password-protected backup ZIP...")
        zip_path = f"VAULT_BACKUP_{user_email}.zip"
        
        with pyzipper.AESZipFile(zip_path, 'w', 
                                  compression=pyzipper.ZIP_DEFLATED,
                                  encryption=pyzipper.WZ_AES) as zf:
            zf.pwd = recovery_token.encode('utf-8')
            for root, dirs, files in os.walk(user_quarantine_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, user_quarantine_dir)
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    zf.writestr(arcname, file_data)
                    print(f"DEBUG: Added {arcname} to ZIP")
        
        print(f"DEBUG: ZIP created, sending email...")
        from app.services.email_service import send_backup_email
        send_backup_email(user_email, recovery_token, zip_path)
        
        os.remove(zip_path)
        shutil.rmtree(user_quarantine_dir)
        print("DEBUG: Cleanup complete")
        
    except Exception as e:
        print(f"Backup Email Failed: {e}")

    if user_email in fake_users_db:
        del fake_users_db[user_email]

    return {
        "status": "VAULT DESTROYED",
        "files_affected": files_moved,
        "recovery_token": recovery_token
    }


# NEW ENDPOINT: Decrypt .enc files with private key
@app.post("/decrypt-file")
async def decrypt_uploaded_file(
    file: UploadFile = File(...),
    private_key: str = Form(...)
):
    """
    Upload an encrypted .enc file and provide the private key to decrypt it.
    Returns the decrypted file as a download.
    """
    try:
        # Read the encrypted file
        file_bytes = await file.read()
        
        if len(file_bytes) < 48:
            raise HTTPException(status_code=400, detail="Invalid encrypted file format")
        
        # Extract encryption components
        salt = file_bytes[:16]
        iv = file_bytes[16:32]
        tag = file_bytes[32:48]
        ciphertext = file_bytes[48:]
        
        # Decrypt
        key, _ = generate_key(private_key.strip(), salt)
        decrypted_data = decrypt_data(ciphertext, tag, iv, key)
        
        if decrypted_data is None:
            raise HTTPException(status_code=400, detail="Decryption failed. Wrong private key.")
        
        # Get original filename (remove .enc extension)
        original_name = file.filename.replace(".enc", "") if file.filename.endswith(".enc") else file.filename
        
        return StreamingResponse(
            io.BytesIO(decrypted_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={original_name}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

