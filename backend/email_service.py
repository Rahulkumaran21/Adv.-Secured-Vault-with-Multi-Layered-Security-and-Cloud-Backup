# SMTP handler for sending keys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from email.mime.base import MIMEBase
from email import encoders


load_dotenv()

SENDER_EMAIL = os.getenv("MAIL_SENDER")
SENDER_PASSWORD = os.getenv("MAIL_PASSWORD")

def send_email(to_email, subject, body):
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("⚠️ Email credentials missing in .env")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Email Failed: {str(e)}")

def send_private_key(to_email, private_key):
    subject = "🔐 Your Secure Vault Key (DO NOT DELETE)"
    body = f"""
    <h2>Secure Vault Registration</h2>
    <p>Welcome. Your vault has been initialized.</p>
    <p><b>Your Private Key:</b></p>
    <pre style="background:#eee; padding:10px; font-size:14px;">{private_key}</pre>
    <p style="color:red;">WARNING: If you lose this key, your data is gone forever.</p>
    """
    send_email(to_email, subject, body)

def send_temp_password(to_email, temp_password):
    """Send temporary password after successful identity verification"""
    subject = "🔐 Vault Access Restored - Temporary Password"
    body = f"""
    <h2 style="color:#22c55e;">Identity Verified Successfully!</h2>
    <p>Your account has been unlocked. Use this temporary password to log in:</p>
    <p><b>Temporary Password:</b></p>
    <pre style="background:#000; color:#0f0; padding:15px; font-size:18px;">{temp_password}</pre>
    <p style="color:#f59e0b; font-weight:bold;">⚠️ IMPORTANT:</p>
    <ul>
        <li>Your old password has been invalidated</li>
        <li>Use this temporary password to log in</li>
        <li>Your private key remains the same</li>
    </ul>
    <p style="color:#666; font-size:12px;">This is an automated security response.</p>
    """
    send_email(to_email, subject, body)

def send_recovery_token(to_email, token):
    subject = "⚠️ Vault Destroyed - Recovery Token"
    body = f"""
    <h2>Vault Emergency Destruction Triggered</h2>
    <p>Your files have been moved to quarantine.</p>
    <p><b>Recovery/Decryption Token:</b></p>
    <pre style="background:#000; color:#0f0; padding:10px;">{token}</pre>
    <p>Use this to unlock your Google Drive backup.</p>
    """
    send_email(to_email, subject, body)
def send_backup_email(to_email, recovery_token, zip_file_path):
    subject = "⚠️ Vault Destroyed - Encrypted Backup Attached"
    
    body = f"""
    <h2 style="color:red;">VAULT EMERGENCY DESTRUCTION TRIGGERED</h2>
    <p>Your files have been quarantined and encrypted.</p>
    <p><b>Recovery Token (Password for ZIP):</b></p>
    <pre style="background:#000; color:#0f0; padding:10px; font-size: 16px;">{recovery_token}</pre>
    <p>The attached ZIP file contains your encrypted vault backup.</p>
    <p style="color:#666; font-size:12px;">This is an automated security response.</p>
    """

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        # Attach the ZIP file
        with open(zip_file_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {os.path.basename(zip_file_path)}",
        )
        msg.attach(part)

        # Send
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Backup email sent to {to_email}")
    except Exception as e:
        print(f"❌ Email Failed: {str(e)}")