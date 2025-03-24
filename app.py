"""
WhatsApp Message Sender MVP
A streamlined Flask application for sending WhatsApp messages with image, text and link.
"""
from flask import Flask, request, render_template, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.utils import secure_filename
import os
import json
import requests
import logging
import pandas as pd
from dotenv import load_dotenv
import base64
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import threading
from datetime import datetime
import tempfile


# Firebase imports
import firebase_admin
from firebase_admin import credentials, storage, firestore

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

LAST_REAL_WEBHOOK_TIME = None

# Upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load environment variables
load_dotenv()
META_VERIFY_TOKEN = os.getenv('META_VERIFY_TOKEN', 'happy')
META_ACCESS_TOKEN = os.getenv('META_ACCESS_TOKEN', '')
META_PHONE_NUMBER_ID = os.getenv('META_PHONE_NUMBER_ID', '')
PRIVATE_KEY_PATH = os.getenv('PRIVATE_KEY_PATH', 'private_key.pem')
PRIVATE_KEY_PASSWORD = os.getenv('PRIVATE_KEY_PASSWORD', '')

# ------------------------------------------------------------------------------
# Firebase Configuration
# ------------------------------------------------------------------------------

class FirebaseManager:
    """Class to manage Firebase operations."""
    
    def __init__(self):
        """Initialize Firebase with credentials from environment or file."""
        self.initialized = False
        try:
            # Check if we have the credentials in an environment variable
            firebase_creds_json = os.getenv('FIREBASE_CREDENTIALS')
            firebase_bucket = os.getenv('FIREBASE_STORAGE_BUCKET')
            
            if firebase_creds_json and firebase_bucket:
                # Create a temporary file to store the credentials
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                    temp_file.write(firebase_creds_json.encode())
                    creds_path = temp_file.name
                    
                # Initialize with the temporary file
                cred = credentials.Certificate(creds_path)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': firebase_bucket
                })
                
                # Clean up the temporary file
                os.unlink(creds_path)
                self.initialized = True
                logger.info("Firebase initialized successfully")
            else:
                # Try to use a credentials file at a predefined path
                creds_path = 'firebase-credentials.json'
                if os.path.exists(creds_path):
                    cred = credentials.Certificate(creds_path)
                    firebase_admin.initialize_app(cred, {
                        'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET')
                    })
                    self.initialized = True
                    logger.info("Firebase initialized from local credentials file")
                else:
                    logger.warning("No Firebase credentials found. Firebase functionality will be disabled.")
        except Exception as e:
            logger.error(f"Firebase initialization error: {str(e)}")
    
    def upload_file(self, local_path, firebase_path=None):
        """Upload a file to Firebase Storage.
        
        Args:
            local_path (str): Path to local file
            firebase_path (str, optional): Custom path in Firebase. Defaults to file basename.
            
        Returns:
            str: Public URL of the file if successful, None otherwise
        """
        if not self.initialized:
            logger.warning("Firebase not initialized, skipping upload")
            return None
            
        try:
            # Use file basename if no firebase path specified
            if not firebase_path:
                firebase_path = os.path.basename(local_path)
            
            # Upload the file
            bucket = storage.bucket()
            blob = bucket.blob(firebase_path)
            blob.upload_from_filename(local_path)
            
            # Make the file publicly accessible
            blob.make_public()
            
            logger.info(f"File uploaded to Firebase: {firebase_path}")
            return blob.public_url
        except Exception as e:
            logger.error(f"Firebase upload error: {str(e)}")
            return None
    
    def download_file(self, firebase_path, local_path, force=False):
        """Download a file from Firebase Storage.
        
        Args:
            firebase_path (str): Path to file in Firebase
            local_path (str): Local path to save file
            force (bool): Whether to overwrite existing file
            
        Returns:
            bool: Success status
        """
        if not self.initialized:
            logger.warning("Firebase not initialized, skipping download")
            return False
            
        # Skip if file exists and force=False
        if os.path.exists(local_path) and not force:
            logger.info(f"File already exists locally: {local_path}")
            return True
            
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Download the file
            bucket = storage.bucket()
            blob = bucket.blob(firebase_path)
            blob.download_to_filename(local_path)
            
            logger.info(f"File downloaded from Firebase: {firebase_path} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Firebase download error: {str(e)}")
            return False
    
    def list_files(self, prefix=None):
        """List files in Firebase Storage.
        
        Args:
            prefix (str, optional): Filter files by prefix
            
        Returns:
            list: List of file paths
        """
        if not self.initialized:
            logger.warning("Firebase not initialized, skipping listing")
            return []
            
        try:
            bucket = storage.bucket()
            blobs = bucket.list_blobs(prefix=prefix)
            return [blob.name for blob in blobs]
        except Exception as e:
            logger.error(f"Firebase listing error: {str(e)}")
            return []
    
    def delete_file(self, firebase_path):
        """Delete a file from Firebase Storage.
        
        Args:
            firebase_path (str): Path to file in Firebase
            
        Returns:
            bool: Success status
        """
        if not self.initialized:
            logger.warning("Firebase not initialized, skipping deletion")
            return False
            
        try:
            bucket = storage.bucket()
            blob = bucket.blob(firebase_path)
            blob.delete()
            
            logger.info(f"File deleted from Firebase: {firebase_path}")
            return True
        except Exception as e:
            logger.error(f"Firebase deletion error: {str(e)}")
            return False
    
    def backup_json(self, data, firebase_path=None):
        """Backup JSON data to Firebase Storage.
        
        Args:
            data (dict): JSON-serializable data
            firebase_path (str, optional): Custom path in Firebase
            
        Returns:
            str: Public URL if successful, None otherwise
        """
        if not self.initialized:
            logger.warning("Firebase not initialized, skipping backup")
            return None
            
        try:
            # Create a temporary file
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                temp_file.write(json.dumps(data, indent=2).encode())
                temp_path = temp_file.name
            
            # Generate path if not provided
            if not firebase_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                firebase_path = f"backups/{timestamp}.json"
            
            # Upload file
            result = self.upload_file(temp_path, firebase_path)
            
            # Clean up
            os.unlink(temp_path)
            return result
        except Exception as e:
            logger.error(f"JSON backup error: {str(e)}")
            return None
    
    def backup_webhook(self, webhook_data):
        """Backup a webhook to Firebase Storage.
        
        Args:
            webhook_data (dict): Webhook data
            
        Returns:
            str: Path in Firebase if successful, None otherwise
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        firebase_path = f"webhooks/{timestamp}_webhook.json"
        return self.backup_json(webhook_data, firebase_path)
    
    def backup_csv(self, file_path='guests.csv', firebase_path=None):
        """Backup CSV file to Firebase.
        
        Args:
            file_path (str): Path to CSV file
            firebase_path (str, optional): Custom path in Firebase
            
        Returns:
            str: Public URL if successful, None otherwise
        """
        if not os.path.exists(file_path):
            logger.warning(f"CSV file not found: {file_path}")
            return None
            
        if not firebase_path:
            firebase_path = f"app_data/{os.path.basename(file_path)}"
            
        return self.upload_file(file_path, firebase_path)
    
    def restore_csv(self, firebase_path='app_data/guests.csv', local_path='guests.csv'):
        """Restore CSV file from Firebase.
        
        Args:
            firebase_path (str): Path in Firebase
            local_path (str): Local path to restore to
            
        Returns:
            bool: Success status
        """
        return self.download_file(firebase_path, local_path)

# Initialize the Firebase manager
firebase = FirebaseManager()

# Function to run periodic backups
def run_periodic_backups():
    """Background thread function for running periodic backups."""
    while True:
        try:
            # Backup CSV files
            if os.path.exists('guests.csv'):
                firebase.backup_csv('guests.csv')
                
            logger.info("Periodic backup completed")
        except Exception as e:
            logger.error(f"Error in periodic backup: {str(e)}")
        
        # Sleep for 1 hour
        time.sleep(3600)

# Start backup thread
backup_thread = threading.Thread(target=run_periodic_backups, daemon=True)
backup_thread.start()

# ------------------------------------------------------------------------------
# login Functions
# ------------------------------------------------------------------------------


# Set a session secret key
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'celinadorsecretkey')

# Set your password
PASSWORD = os.getenv('APP_PASSWORD', 'CelinaDorWedding2025!')

# Simple gate middleware
@app.before_request
def check_auth():
    # Skip auth check for static files, login route, and webhook endpoints
    if (request.path.startswith('/static') or 
        request.path == '/login' or 
        request.path.startswith('/meta-webhook') or
        request.path.startswith('/flow-webhook') or
        'webhook' in request.path.lower()):
        return None
    
    # Check if the user is authenticated
    if not session.get('authenticated'):
        return redirect('/login')
    
    return None

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        
        # Password is incorrect
        return render_template('login.html', error='Incorrect password')
    
    # GET request - show the login form
    return render_template('login.html')

# Logout route (optional)
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------
def allowed_file(filename):
    """Check if file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_guests():
    """Load or create guests CSV file with Firebase backup."""
    if not os.path.exists('guests.csv'):
        # Try to restore from backup
        firebase.restore_csv('app_data/guests.csv', 'guests.csv')
        
        # If still doesn't exist, create new one
        if not os.path.exists('guests.csv'):
            pd.DataFrame(columns=['name', 'phone'])\
              .to_csv('guests.csv', index=False)
    
    return pd.read_csv('guests.csv')

def upload_image_to_meta(image_path):
    """
    Upload an image to Meta's servers to get a media ID.
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        str: Media ID if successful, None otherwise
    """
    try:
        url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/media"
        
        # Determine content type based on file extension
        content_type = None
        if image_path.lower().endswith('.jpg') or image_path.lower().endswith('.jpeg'):
            content_type = 'image/jpeg'
        elif image_path.lower().endswith('.png'):
            content_type = 'image/png'
        elif image_path.lower().endswith('.webp'):
            content_type = 'image/webp'
        else:
            logger.error(f"Unsupported image format: {image_path}")
            return None
        
        logger.debug(f"Uploading image with content type: {content_type}")
        
        with open(image_path, 'rb') as image_file:
            files = {
                'file': (os.path.basename(image_path), image_file, content_type)
            }
            
            data = {
                'messaging_product': 'whatsapp'
            }
            
            headers = {
                'Authorization': f'Bearer {META_ACCESS_TOKEN}'
            }
            
            response = requests.post(url, headers=headers, data=data, files=files)
            
            logger.debug(f"Upload response status: {response.status_code}")
            logger.debug(f"Upload response text: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                
                # Backup the image to Firebase
                if firebase.initialized:
                    firebase.upload_file(image_path, f"whatsapp_images/{os.path.basename(image_path)}")
                
                logger.info(f"Image uploaded successfully: {result}")
                return result.get('id')
            else:
                logger.error(f"Failed to upload image: {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error uploading image: {str(e)}")
        return None

def send_whatsapp_template(phone_number, template_name=None, template_language=None, message_text=None, link_url=None, image_id=None):
    """
    Send a WhatsApp message using a pre-approved template.
    
    Args:
        phone_number (str): Recipient's phone number
        template_name (str, optional): Name of the approved template
            - "rsvp_massage_visit_web" - Template with image header and URL button
            - "auto_reply_webhook" - Simple text template for automated responses
            - Default is determined by the provided parameters
        template_language (str, optional): Language code for the template
            - Default depends on the template (en_US for rsvp_massage_visit_web, en for auto_reply_webhook)
        message_text (str, optional): 
            - This is ignored for current templates as they don't support dynamic body text
            - Kept for future templates that might support it
        link_url (str, optional): 
            - URL to override the default button URL for templates with buttons
            - Ignored for templates without URL buttons
        image_id (str, optional): 
            - Media ID for header image for templates with image headers
            - Ignored for templates without image headers
        
    Returns:
        bool: Success status
    """
    # Ensure phone number is properly formatted
    phone_str = str(phone_number)
    if not phone_str.startswith('+'):
        phone_str = f'+{phone_str}'
    
    # Determine the template to use based on provided parameters
    if not template_name:
        if image_id or link_url:
            template_name = "rsvp_massage_visit_web"
            if not template_language:
                template_language = "en_US"
        else:
            template_name = "auto_reply_webhook"
            if not template_language:
                template_language = "en"
    elif template_name == "rsvp_massage_visit_web" and not template_language:
        template_language = "en_US"
    elif template_name == "auto_reply_webhook" and not template_language:
        template_language = "en"
        
    url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/messages"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {META_ACCESS_TOKEN}"
    }
    
    # Base template message data
    data = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": phone_str,
        "type": "template",
        "template": {
            "name": template_name,
            "language": {
                "code": template_language
            }
        }
    }
    
    # Add components based on template type
    components = []
    
    if template_name == "rsvp_massage_visit_web":
        # Add header component with image
        if image_id:
            components.append({
                "type": "header",
                "parameters": [
                    {
                        "type": "image",
                        "image": {
                            "id": image_id
                        }
                    }
                ]
            })
        else:
            # Fallback to default image if no image_id provided
            components.append({
                "type": "header",
                "parameters": [
                    {
                        "type": "image",
                        "image": {
                            "link": "https://celinador.wixsite.com/wedding/logo.jpg"
                        }
                    }
                ]
            })
        
        # IMPORTANT: Do NOT add a body component for rsvp_massage_visit_web
        # The template doesn't support dynamic body text
        
        # Add URL button override if provided
        if link_url:
            if not (link_url.startswith('http://') or link_url.startswith('https://')):
                link_url = 'https://' + link_url
                
            components.append({
                "type": "button",
                "sub_type": "url",
                "index": "0",  # First button (0-indexed)
                "parameters": [
                    {
                        "type": "text",
                        "text": link_url
                    }
                ]
            })
            
        # Add components to the template data if we have any
        if components:
            data["template"]["components"] = components
    
    # For "auto_reply_webhook" and other simple templates without customizable components,
    # we don't need to add any components
    
    # Send the request
    try:
        logger.debug(f"Sending template message to {phone_str}")
        logger.debug(f"Request data: {json.dumps(data, indent=2)}")
        
        response = requests.post(url, headers=headers, json=data)
        result = response.json()
        
        logger.debug(f"Template response status: {response.status_code}")
        logger.debug(f"Template response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 200:
            logger.info(f"Template message sent successfully: {result}")
            return True
        else:
            logger.error(f"Failed to send template message: {result}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending template message: {str(e)}")
        return False

def send_dynamic_template(phone_number, template_data):
    """
    Send a WhatsApp template message with dynamic components.
    
    Args:
        phone_number (str): Recipient's phone number
        template_data (dict): Template information including:
            - template_name: Name of the template
            - components: List of component objects
        
    Returns:
        bool: Success status
    """
    # Ensure phone number is properly formatted
    phone_str = str(phone_number)
    if not phone_str.startswith('+'):
        phone_str = f'+{phone_str}'
    
    # Get template name and components
    template_name = template_data.get('template_name')
    components = template_data.get('components', [])
    
    # Create the API request
    url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/messages"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {META_ACCESS_TOKEN}"
    }
    
    # Base template message data
    data = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": phone_str,
        "type": "template",
        "template": {
            "name": template_name,
            "language": {
                "code": "en_US"  # Default to English, could be dynamic
            }
        }
    }
    
    # Add components if any
    if components:
        data["template"]["components"] = components
    
    try:
        logger.debug(f"Sending template '{template_name}' to {phone_str}")
        logger.debug(f"Request data: {json.dumps(data, indent=2)}")
        
        response = requests.post(url, headers=headers, json=data)
        result = response.json()
        
        logger.debug(f"Template response status: {response.status_code}")
        logger.debug(f"Template response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 200:
            logger.info(f"Template message sent successfully: {result}")
            return True
        else:
            logger.error(f"Failed to send template message: {result}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending template message: {str(e)}")
        return False

def extract_messages_from_webhook(data):
    """
    Extract messages from webhook data in various possible formats.
    
    Args:
        data (dict): Webhook data
        
    Returns:
        list: List of extracted message objects
    """
    messages = []
    
    try:
        # Format 1: entry -> changes -> value -> messages
        if 'entry' in data:
            for entry in data['entry']:
                if 'changes' in entry:
                    for change in entry['changes']:
                        if 'value' in change and 'messages' in change['value']:
                            messages.extend(change['value']['messages'])
                
                # Format 2: entry -> messaging
                if 'messaging' in entry:
                    for item in entry['messaging']:
                        if 'message' in item:
                            # Transform to standard format
                            messages.append({
                                'from': item.get('sender', {}).get('id'),
                                'id': item.get('message', {}).get('mid'),
                                'timestamp': item.get('timestamp'),
                                'type': 'text',
                                'text': {
                                    'body': item.get('message', {}).get('text', '')
                                }
                            })
        
        logger.debug(f"Extracted {len(messages)} messages from webhook")
        
        # Log detailed message info for debugging
        for i, msg in enumerate(messages):
            logger.debug(f"Message {i+1}:")
            logger.debug(f"  From: {msg.get('from')}")
            logger.debug(f"  Type: {msg.get('type')}")
            if msg.get('type') == 'text' and 'text' in msg:
                logger.debug(f"  Content: {msg['text'].get('body')}")
                
    except Exception as e:
        logger.error(f"Error extracting messages: {str(e)}")
        
    return messages

def extract_message_content(message):
    """Extract readable content from a message object."""
    message_type = message.get('type', '')
    
    if message_type == 'text' and 'text' in message:
        return message['text'].get('body', 'No content')
    elif message_type == 'image' and 'image' in message:
        return f"Image: {message['image'].get('caption', 'No caption')}"
    elif message_type == 'document' and 'document' in message:
        return f"Document: {message['document'].get('filename', 'Unknown file')}"
    elif message_type == 'audio' and 'audio' in message:
        return "Audio message"
    elif message_type == 'video' and 'video' in message:
        return f"Video: {message['video'].get('caption', 'No caption')}"
    elif message_type == 'location' and 'location' in message:
        location = message['location']
        return f"Location: {location.get('name', 'Unknown')} ({location.get('latitude', '?')}, {location.get('longitude', '?')})"
    else:
        return f"Unsupported message type: {message_type}"

# ------------------------------------------------------------------------------
# Encryption & Decryption Functions
# ------------------------------------------------------------------------------
def load_private_key(key_path, password=None):
    """Load the RSA private key from a PEM file."""
    try:
        logger.info(f"Loading RSA private key from: {key_path}")
        
        # Check if the file exists
        if not os.path.exists(key_path):
            error_msg = f"Private key file not found: {key_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
            
        with open(key_path, 'rb') as key_file:
            key_data = key_file.read()

        # Load the private key (PKCS#1 or PKCS#8)
        try:
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password.encode('utf-8') if password else None,
                backend=default_backend()
            )
        except ValueError as e:
            if "bad password" in str(e).lower():
                error_msg = "Incorrect password for private key"
            else:
                error_msg = f"Invalid private key format: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Ensure it's RSA
        if not isinstance(private_key, rsa.RSAPrivateKey):
            error_msg = "Key must be an RSA private key"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        logger.info(f"Loaded private key successfully: {type(private_key)}")
        return private_key
        
    except Exception as e:
        logger.error(f"Error loading private key: {str(e)}")
        raise

def decrypt_aes_key(encrypted_aes_key, private_key):
    """Decrypt the AES key using the private RSA key."""
    try:
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_aes_key
    except Exception as e:
        logger.error(f"AES key decryption error: {str(e)}")
        raise

def decrypt_flow_data(encrypted_data, encrypted_aes_key, initial_vector):
    """Decrypt flow data using the encrypted AES key and IV."""
    try:
        # Load the private key
        private_key_path = PRIVATE_KEY_PATH
        private_key_password = PRIVATE_KEY_PASSWORD
        private_key = load_private_key(private_key_path, private_key_password)
        
        # Decrypt the AES key
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        
        # Extract the AES-GCM authentication tag (last 16 bytes)
        tag_length = 16
        encrypted_flow_data_body = encrypted_data[:-tag_length]
        encrypted_flow_data_tag = encrypted_data[-tag_length:]
        
        # Decrypt the flow data with AES-GCM
        cipher = Cipher(
            algorithms.AES(decrypted_aes_key),
            modes.GCM(initial_vector, encrypted_flow_data_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_flow_data_body) + decryptor.finalize()
        
        # Parse JSON data
        return json.loads(decrypted_data.decode('utf-8'))
        
    except Exception as e:
        logger.error(f"Flow data decryption error: {str(e)}")
        raise

def encrypt_response(response_data, request_body):
    """Encrypt the response payload using AES-GCM."""
    try:
        # Extract encrypted data from request
        encrypted_aes_key = base64.b64decode(request_body['encrypted_aes_key'])
        initial_vector = base64.b64decode(request_body['initial_vector'])
        
        # Load the private key
        private_key_path = PRIVATE_KEY_PATH
        private_key_password = PRIVATE_KEY_PASSWORD
        private_key = load_private_key(private_key_path, private_key_password)
        
        # Decrypt the AES key
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        
        # Convert response to JSON and then to bytes
        response_json = json.dumps(response_data)
        response_bytes = response_json.encode('utf-8')
        
        # Flip/invert the initialization vector for response encryption
        flipped_iv = bytes(b ^ 0xFF for b in initial_vector)
        
        # Encrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(flipped_iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(response_bytes) + encryptor.finalize()
        
        # Append authentication tag and return base64-encoded
        encrypted_response = encrypted_data + encryptor.tag
        return base64.b64encode(encrypted_response).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Response encryption error: {str(e)}")
        raise

def initialize_app_files():
    """Initialize necessary files and directories for the application."""
    # Create uploads directory
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Create webhook_logs directory
    os.makedirs('webhook_logs', exist_ok=True)
    
    # Initialize guests.csv if it doesn't exist
    if not os.path.exists('guests.csv'):
        # Try to restore from backup
        firebase.restore_csv('app_data/guests.csv', 'guests.csv')
        
        # If still doesn't exist, create new one
        if not os.path.exists('guests.csv'):
            pd.DataFrame(columns=['name', 'phone']).to_csv('guests.csv', index=False)
    
    # Create empty webhook files if needed
    if not os.path.exists('last_webhook.json'):
        with open('last_webhook.json', 'w') as f:
            f.write('{}')
    
    logger.info("Application files initialized successfully")

def initialize_private_key():
    """Initialize private key from environment variable if available."""
    private_key_base64 = os.getenv('PRIVATE_KEY_BASE64')
    if private_key_base64:
        import base64
        # Decode the base64 private key
        private_key_data = base64.b64decode(private_key_base64)
        # Write to file
        with open(PRIVATE_KEY_PATH, 'wb') as key_file:
            key_file.write(private_key_data)
        logger.info(f"Private key initialized from environment variable")
        return True
    else:
        logger.warning(f"No private key found in environment variables")
        return False

# ------------------------------------------------------------------------------
# WhatsApp Business App Sync Functions
# ------------------------------------------------------------------------------
def initiate_contacts_sync(phone_number_id=None):
    """
    Initiate contacts synchronization for WhatsApp Business app.
    
    Args:
        phone_number_id (str, optional): Phone number ID to sync contacts for.
            If not provided, uses the default phone number ID.
            
    Returns:
        dict: API response
    """
    if not phone_number_id:
        phone_number_id = META_PHONE_NUMBER_ID
        
    url = f"https://graph.facebook.com/v18.0/{phone_number_id}/smb_app_data"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {META_ACCESS_TOKEN}"
    }
    
    data = {
        "messaging_product": "whatsapp",
        "sync_type": "smb_app_state_sync"
    }
    
    response = requests.post(url, headers=headers, json=data)
    return response.json()

def initiate_history_sync(phone_number_id=None):
    """
    Initiate message history synchronization for WhatsApp Business app.
    
    Args:
        phone_number_id (str, optional): Phone number ID to sync history for.
            If not provided, uses the default phone number ID.
            
    Returns:
        dict: API response
    """
    if not phone_number_id:
        phone_number_id = META_PHONE_NUMBER_ID
        
    url = f"https://graph.facebook.com/v18.0/{phone_number_id}/smb_app_data"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {META_ACCESS_TOKEN}"
    }
    
    data = {
        "messaging_product": "whatsapp",
        "sync_type": "history"
    }
    
    response = requests.post(url, headers=headers, json=data)
    return response.json()

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.route('/keep-alive')
def keep_alive():
    """Simple endpoint for keep-alive pings."""
    return jsonify({
        "status": "ok",
        "timestamp": time.time(),
        "message": "WhatsApp Message Sender is alive"
    })

@app.route('/api-check', methods=['GET'])
def api_check():
    """Check the WhatsApp API connection and credentials."""
    try:
        # Verify we have the necessary credentials
        if not META_ACCESS_TOKEN:
            return jsonify({
                'status': 'error',
                'message': 'META_ACCESS_TOKEN is not configured'
            }), 400

        if not META_PHONE_NUMBER_ID:
            return jsonify({
                'status': 'error',
                'message': 'META_PHONE_NUMBER_ID is not configured'
            }), 400
            
        # Try to get phone number information from Meta API
        url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
        headers = {
            "Authorization": f"Bearer {META_ACCESS_TOKEN}"
        }
        
        logger.debug(f"Testing API connection to {url}")
        response = requests.get(url, headers=headers)
        
        # Log full response for debugging
        logger.debug(f"API check response status: {response.status_code}")
        logger.debug(f"API check response: {response.text}")
        
        # Return the response data
        if response.status_code == 200:
            return jsonify({
                'status': 'success',
                'message': 'API connection successful',
                'data': response.json()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'API error: {response.status_code}',
                'details': response.json()
            }), 400
            
    except Exception as e:
        logger.error(f"Error checking API: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Exception: {str(e)}'
        }), 500

@app.route('/')
def home():
    """Main page route: shows guests and message form."""
    try:
        df = load_guests()
        return render_template('index.html', guests=df.to_dict('records'))
    except Exception as e:
        logger.error(f"Error rendering home page: {str(e)}")
        return f"Error loading home page: {str(e)}", 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    """Upload an image for WhatsApp messages."""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image part'}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        # Log the uploaded file's content type
        logger.debug(f"Received file: {file.filename}, Content-Type: {file.content_type}")
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            logger.debug(f"Saved file to {filepath}")
            
            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size > 5 * 1024 * 1024:  # 5MB
                os.remove(filepath)  # Clean up
                return jsonify({'error': 'File size exceeds 5MB limit'}), 400
            
            # Upload to Meta and get media ID
            media_id = upload_image_to_meta(filepath)
            
            if media_id:
                return jsonify({
                    'success': True,
                    'filename': filename,
                    'media_id': media_id,
                    'filepath': f'/uploads/{filename}'
                })
            else:
                # Return more specific error information
                return jsonify({'error': 'Failed to upload to Meta API. Check server logs for details.'}), 500
        else:
            return jsonify({'error': f'File type not allowed. Please use JPG, JPEG, or PNG images.'}), 400
    except Exception as e:
        logger.error(f"Error in upload_image route: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    """Send WhatsApp message to selected recipients using templates."""
    data = request.json
    selected_phones = data.get('selected_phones', [])
    template_data = data.get('template_data', {})
    
    if not template_data or not template_data.get('template_name'):
        return jsonify({'error': 'Template information is required'}), 400
        
    if not selected_phones:
        return jsonify({'error': 'No recipients selected'}), 400
    
    success_count = 0
    failed_phones = []
    
    for phone in selected_phones:
        try:
            # Send template message using direct API call
            if send_dynamic_template(phone, template_data):
                success_count += 1
            else:
                failed_phones.append(phone)
        except Exception as e:
            logger.error(f"Error sending to {phone}: {str(e)}")
            failed_phones.append(phone)
    
    # Construct response
    message = f"Successfully sent {success_count} messages"
    if failed_phones:
        message += f" ({len(failed_phones)} failed)"
    
    return jsonify({
        'success': True,
        'message': message,
        'failed': failed_phones if failed_phones else None,
        'success_count': success_count,
        'total_attempted': len(selected_phones)
    })

@app.route('/meta-webhook', methods=['GET', 'POST'])
def meta_webhook():
    """Handle Meta webhook for WhatsApp verification and messages."""
    logger.debug("=== Webhook Request Received ===")
    logger.debug(f"Method: {request.method}")
    logger.debug(f"Headers: {dict(request.headers)}")

    global LAST_REAL_WEBHOOK_TIME
    LAST_REAL_WEBHOOK_TIME = datetime.now()  # This will work after adding the import
    
    if request.method == 'GET':
        # Verification parameters
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')

        logger.info(f"Verification attempt with mode={mode}, token={token}")

        # Validate verification
        if mode == "subscribe" and token == META_VERIFY_TOKEN:
            logger.info("Verification successful! Returning challenge.")
            return challenge, 200
        else:
            logger.warning(f"Verification failed! Expected token: {META_VERIFY_TOKEN}, Got: {token}")
            return "Forbidden", 403

    elif request.method == 'POST':
        try:
            # Get the raw request data for debugging
            raw_data = request.get_data()
            logger.debug(f"Raw webhook data: {raw_data}")
            
            print("\n🔔 WEBHOOK RECEIVED! 🔔\n", flush=True)
            
            # Parse as JSON
            data = request.json
            logger.debug(f"Webhook data: {json.dumps(data, indent=2)}")
            
            # Save the webhook data
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            with open('last_webhook.json', 'w') as f:
                json.dump(data, f, indent=2)
            
            os.makedirs('webhook_logs', exist_ok=True)
            with open(f'webhook_logs/{timestamp}_webhook.json', 'w') as f:
                json.dump(data, f, indent=2)
            
            # Backup to Firebase
            if firebase.initialized:
                firebase.backup_webhook(data)
            
            # Extract messages using our helper function
            messages = extract_messages_from_webhook(data)
            
            # For any object type, also find and extract phone numbers recursively
            phone_numbers = []
            
            def extract_phones(obj, path=""):
                """Recursively extract phone numbers from any object"""
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if key == 'from' and isinstance(value, str):
                            phone_numbers.append(value.strip())
                            print(f"Found phone number '{value}' at {path}.{key}")
                        elif key == 'wa_id' and isinstance(value, str):
                            phone_numbers.append(value.strip())
                            print(f"Found wa_id '{value}' at {path}.{key}")
                        elif isinstance(value, (dict, list)):
                            extract_phones(value, f"{path}.{key}")
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        extract_phones(item, f"{path}[{i}]")
            
            # Extract phones from the entire webhook
            extract_phones(data)
            
            # Remove duplicates from both sources
            unique_phones = list(set(phone_numbers))
            
            # Add phones from messages if not already in the list
            for message in messages:
                if 'from' in message and message['from'] not in unique_phones:
                    unique_phones.append(message['from'])
            
            if unique_phones:
                print(f"Found {len(unique_phones)} unique phone numbers in webhook: {unique_phones}")
                
                # Send auto-reply using template to each unique phone
                for phone in unique_phones:
                    print(f"Sending auto-reply template to {phone}")
                    
                    # Use the unified template function
                    success = send_whatsapp_template(
                        phone_number=phone, 
                        template_name="auto_reply_webhook"
                    )
                    
                    if success:
                        logger.info(f"✅ Auto-reply template sent to {phone}")
                    else:
                        logger.error(f"❌ Failed to send auto-reply template to {phone}")
            else:
                logger.warning("No phone numbers found in webhook data")
            
            return 'OK'
        except Exception as e:
            logger.error(f"Error processing webhook: {str(e)}")
            logger.exception("Full traceback:")
            return 'Error', 500

@app.route('/check-last-webhook')
def check_last_webhook():
    """Check when the last real webhook was received."""
    if LAST_REAL_WEBHOOK_TIME:
        time_ago = datetime.now() - LAST_REAL_WEBHOOK_TIME
        minutes_ago = time_ago.total_seconds() / 60
        return jsonify({
            "last_webhook_time": LAST_REAL_WEBHOOK_TIME.strftime("%Y-%m-%d %H:%M:%S"),
            "minutes_ago": round(minutes_ago, 1),
            "received_recently": minutes_ago < 5
        })
    else:
        return jsonify({
            "last_webhook_time": None,
            "message": "No webhooks received since server start"
        })
        
@app.route('/get-waba-id')
def get_waba_id():
    """Get the WhatsApp Business Account ID."""
    try:
        # Get phone number details
        url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
        headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
        
        response = requests.get(url, headers=headers)
        phone_data = response.json()
        
        # Extract WABA ID
        waba_id = phone_data.get('whatsapp_business_account_id')
        
        return jsonify({
            "phone_number_id": META_PHONE_NUMBER_ID,
            "phone_data": phone_data,
            "waba_id": waba_id
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/update-webhook-subscription', methods=['GET'])
def update_webhook_subscription():
    """Update webhook subscription fields."""
    try:
        if not META_ACCESS_TOKEN or not META_PHONE_NUMBER_ID:
            return jsonify({
                "status": "error",
                "message": "Missing Meta credentials"
            }), 400
        
        # Fields we want to subscribe to
        fields = [
            "messages", 
            "message_status_updates",
            "message_template_status_updates"
        ]
        
        # GET to check current subscriptions
        get_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/subscribed_apps"
        headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
        
        get_response = requests.get(get_url, headers=headers)
        current_subscriptions = get_response.json().get('data', [])
        
        # POST to update subscriptions
        post_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/subscribed_apps"
        
        post_data = {
            "field_name": fields
        }
        
        post_response = requests.post(post_url, headers=headers, json=post_data)
        update_result = post_response.json()
        
        return jsonify({
            "status": "success",
            "previous_subscriptions": current_subscriptions,
            "update_result": update_result
        })
    except Exception as e:
        logger.exception("Error updating webhook subscription:")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/webhook-test-tool')
def webhook_test_tool():
    """Provide a tool to analyze webhook logs."""
    try:
        # Get all webhook log files
        webhook_logs = []
        if os.path.exists('webhook_logs'):
            for filename in sorted(os.listdir('webhook_logs'), reverse=True):
                if filename.endswith('.json'):
                    with open(os.path.join('webhook_logs', filename), 'r') as f:
                        try:
                            data = json.load(f)
                            webhook_logs.append({
                                'filename': filename,
                                'timestamp': filename.split('_')[0],
                                'data': data
                            })
                        except:
                            pass
        
        # Check last_webhook.json
        last_webhook = None
        if os.path.exists('last_webhook.json'):
            try:
                with open('last_webhook.json', 'r') as f:
                    last_webhook = json.load(f)
            except:
                pass
        
        return render_template('webhook_tool.html', 
                              last_webhook=last_webhook,
                              webhook_logs=webhook_logs[:10],  # Just show the 10 most recent
                              meta_phone_number_id=META_PHONE_NUMBER_ID)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/flow-webhook', methods=['GET', 'POST'])
def flow_webhook():
    """Handle WhatsApp Flow webhook requests from Meta."""
    try:
        logger.debug("=== Flow Webhook Request Received ===")
        
        # GET request for verification
        if request.method == 'GET':
            return "OK", 200

        # Check JSON payload
        if not request.is_json:
            return jsonify({"error": "Invalid payload format"}), 400

        # Parse request body
        body = request.json
        logger.debug(f"flow-webhook received JSON:\n{json.dumps(body, indent=2)}")
        
        # Store the webhook data for analysis
        with open('last_flow_webhook.json', 'w') as f:
            json.dump(body, f, indent=2)

        # Check if this is a ping action
        if 'action' in body and body['action'] == 'ping' and 'encrypted_flow_data' not in body:
            return json.dumps({"data": {"status": "active"}}), 200, {'Content-Type': 'application/json'}

        # Make sure we have the required encryption fields
        required_fields = ['encrypted_flow_data', 'encrypted_aes_key', 'initial_vector']
        for field in required_fields:
            if field not in body:
                return jsonify({"error": f"Missing {field}"}), 400
        
        # Decode base64 fields
        encrypted_flow_data = base64.b64decode(body['encrypted_flow_data'])
        encrypted_aes_key = base64.b64decode(body['encrypted_aes_key'])
        initial_vector = base64.b64decode(body['initial_vector'])
        
        # Decrypt the request
        try:
            decrypted_data = decrypt_flow_data(encrypted_flow_data, encrypted_aes_key, initial_vector)
            logger.info(f"Decrypted flow data: {decrypted_data}")
            
            # Handle ping action (from encrypted request)
            if decrypted_data.get('action') == 'ping':
                ping_response = {"data": {"status": "active"}}
                encrypted_response = encrypt_response(ping_response, body)
                return encrypted_response, 200, {'Content-Type': 'text/plain'}
            
            # Handle other data exchange actions
            else:
                response_data = {
                    "screen": "SUCCESS",
                    "data": {
                        "message": "Flow data processed successfully"
                    }
                }
                
                encrypted_response = encrypt_response(response_data, body)
                return encrypted_response, 200, {'Content-Type': 'text/plain'}
            
        except Exception as e:
            logger.error(f"Error processing encrypted data: {str(e)}")
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 421

    except Exception as e:
        logger.error(f"Unexpected error in flow_webhook: {str(e)}")
        return jsonify({"error": "Unexpected server error"}), 500

@app.route('/webhook-diagnostic', methods=['GET'])
def webhook_diagnostic():
    """Diagnose webhook configuration."""
    diagnostic_info = {
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "meta_verify_token": META_VERIFY_TOKEN[:3] + "..." if META_VERIFY_TOKEN else "Not set",
        "meta_phone_number_id": META_PHONE_NUMBER_ID[:3] + "..." if META_PHONE_NUMBER_ID else "Not set",
        "webhook_file_exists": os.path.exists('last_webhook.json'),
        "webhook_file_timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime('last_webhook.json'))) if os.path.exists('last_webhook.json') else "N/A",
        "webhook_file_size": os.path.getsize('last_webhook.json') if os.path.exists('last_webhook.json') else 0,
    }
    
    # Test sending a message to yourself
    test_message = None
    if META_PHONE_NUMBER_ID and META_ACCESS_TOKEN:
        try:
            # Try to get the phone number information as a basic API test
            url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
            headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
            response = requests.get(url, headers=headers)
            diagnostic_info["api_test_status"] = response.status_code
            diagnostic_info["api_test_response"] = response.json() if response.status_code == 200 else response.text
        except Exception as e:
            diagnostic_info["api_test_error"] = str(e)
    
    return jsonify(diagnostic_info)

@app.route('/test-webhook', methods=['GET'])
def test_webhook():
    """Manually simulate a webhook for testing."""
    try:
        # Get your phone number to test with
        test_phone = request.args.get('phone', '')
        if not test_phone:
            return jsonify({
                "status": "error",
                "message": "Please provide a phone number using ?phone=1234567890"
            }), 400
            
        # Format phone number if needed
        if test_phone.startswith('+'):
            test_phone = test_phone[1:]
            
        # Create a sample webhook payload based on Meta's sample
        sample_webhook = {
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "12345",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": META_PHONE_NUMBER_ID,
                            "phone_number_id": META_PHONE_NUMBER_ID
                        },
                        "contacts": [{
                            "profile": {
                                "name": "Test User"
                            },
                            "wa_id": test_phone
                        }],
                        "messages": [{
                            "from": test_phone,
                            "id": "wamid.test123",
                            "timestamp": str(int(time.time())),
                            "type": "text",
                            "text": {
                                "body": "This is a test message"
                            }
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }
        
        # Process as if it were a real webhook
        with app.test_client() as client:
            response = client.post('/meta-webhook', 
                                  json=sample_webhook,
                                  headers={'Content-Type': 'application/json'})
        
        return jsonify({
            "status": "success",
            "webhook_response_code": response.status_code,
            "webhook_response_text": response.data.decode('utf-8'),
            "message": "Test webhook processed. Check server logs for details.",
            "test_phone": test_phone
        })
    except Exception as e:
        logger.exception("Error in test webhook:")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/test-send', methods=['GET'])
def test_send():
    """Test sending a WhatsApp message directly."""
    try:
        # Get phone number from query parameter
        test_phone = request.args.get('phone', '')
        if not test_phone:
            return jsonify({
                "status": "error",
                "message": "Please provide a phone number using ?phone=1234567890"
            }), 400
            
        # Get template name from query parameter (optional)
        template_name = request.args.get('template', 'auto_reply_webhook')
        
        # Get message text from query parameter (optional)
        message_text = request.args.get('message', None)
        
        # Send template message using our unified function
        success = send_whatsapp_template(
            phone_number=test_phone,
            template_name=template_name,
            message_text=message_text
        )
        
        if success:
            return jsonify({
                "status": "success",
                "message": f"Test template message '{template_name}' sent to {test_phone}"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to send test template message. Check server logs."
            }), 400
    except Exception as e:
        logger.exception("Error in test send:")
        return jsonify({
            "status": "error", 
            "message": str(e)
        }), 500

@app.route('/webhook-logs')
def webhook_logs():
    """Display all incoming webhooks with message details."""
    try:
        # Read the stored webhook data if it exists
        webhooks = []
        
        # Check if last_webhook.json exists
        if os.path.exists('last_webhook.json'):
            with open('last_webhook.json', 'r') as f:
                try:
                    webhook_data = json.load(f)
                    webhooks.append({
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', 
                                     time.localtime(os.path.getmtime('last_webhook.json'))),
                        'data': webhook_data
                    })
                except json.JSONDecodeError:
                    logger.error("Failed to parse last_webhook.json")
        
        # Also check for any historical webhook logs if you've been saving them
        webhook_log_dir = 'webhook_logs'
        if os.path.exists(webhook_log_dir) and os.path.isdir(webhook_log_dir):
            for filename in sorted(os.listdir(webhook_log_dir), reverse=True):
                if filename.endswith('.json'):
                    with open(os.path.join(webhook_log_dir, filename), 'r') as f:
                        try:
                            webhook_data = json.load(f)
                            # Extract timestamp from filename (assuming format like timestamp_webhook.json)
                            timestamp = filename.split('_')[0]
                            webhooks.append({
                                'timestamp': timestamp,
                                'data': webhook_data
                            })
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse {filename}")
        
        # Parse the webhooks to extract message details
        message_logs = []
        for webhook in webhooks:
            timestamp = webhook['timestamp']
            data = webhook['data']
            
            # Parse the webhook data to extract message details
            if 'entry' in data and len(data['entry']) > 0:
                for entry in data['entry']:
                    # Check for messages in different possible structures
                    
                    # Structure 1: changes -> value -> messages
                    if 'changes' in entry:
                        for change in entry['changes']:
                            if 'value' in change and 'messages' in change['value']:
                                for message in change['value']['messages']:
                                    message_log = {
                                        'timestamp': timestamp,
                                        'from': message.get('from', 'Unknown'),
                                        'to': message.get('to', 'Unknown'),
                                        'wa_id': message.get('id', 'Unknown'),
                                        'message_type': message.get('type', 'Unknown'),
                                        'content': extract_message_content(message)
                                    }
                                    message_logs.append(message_log)
                    
                    # Structure 2: messages
                    if 'messages' in entry:
                        for message in entry['messages']:
                            message_log = {
                                'timestamp': timestamp,
                                'from': message.get('from', 'Unknown'),
                                'to': message.get('to', 'Unknown'),
                                'wa_id': message.get('id', 'Unknown'),
                                'message_type': message.get('type', 'Unknown'),
                                'content': extract_message_content(message)
                            }
                            message_logs.append(message_log)
                    
                    # Structure 3: messaging
                    if 'messaging' in entry:
                        for message_event in entry['messaging']:
                            sender = message_event.get('sender', {}).get('id', 'Unknown')
                            recipient = message_event.get('recipient', {}).get('id', 'Unknown')
                            message = message_event.get('message', {})
                            message_log = {
                                'timestamp': timestamp,
                                'from': sender,
                                'to': recipient,
                                'wa_id': message.get('mid', 'Unknown'),
                                'message_type': 'text' if 'text' in message else 'other',
                                'content': message.get('text', 'Unknown content')
                            }
                            message_logs.append(message_log)
        
        return render_template('webhook_logs.html', message_logs=message_logs)
    except Exception as e:
        logger.error(f"Error rendering webhook logs: {str(e)}")
        logger.exception("Full traceback:")
        return f"Error loading webhook logs: {str(e)}", 500

@app.route('/check-whatsapp-status')
def check_whatsapp_status():
    """Check WhatsApp Business API status and sandbox mode."""
    try:
        # Check the phone number information
        url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
        headers = {
            "Authorization": f"Bearer {META_ACCESS_TOKEN}"
        }
        
        response = requests.get(url, headers=headers)
        result = response.json()
        
        # Get info about the WhatsApp Business Account
        waba_id = result.get('whatsapp_business_account_id', 'Unknown')
        if waba_id != 'Unknown':
            waba_url = f"https://graph.facebook.com/v18.0/{waba_id}"
            waba_response = requests.get(waba_url, headers=headers)
            waba_result = waba_response.json()
        else:
            waba_result = {"error": "Could not determine WABA ID"}
        
        return jsonify({
            "status": "success",
            "phone_number_info": result,
            "waba_info": waba_result,
            "is_sandbox": result.get('quality_rating', 'NA') == 'NA',  # Approximation
            "meta_phone_number_id": META_PHONE_NUMBER_ID,
            "meta_verify_token": META_VERIFY_TOKEN[:3] + "..." if META_VERIFY_TOKEN else "Not set"
        })
    except Exception as e:
        logger.exception("Error checking WhatsApp status:")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/send-template', methods=['POST'])
def send_template():
    """Send a template message via API."""
    try:
        data = request.json
        phone = data.get('phone', '')
        template = data.get('template', 'auto_reply_webhook')
        language = data.get('language', '')
        message_text = data.get('message_text', None)
        link_url = data.get('link_url', None)
        image_id = data.get('image_id', None)
        
        if not phone:
            return jsonify({
                'success': False,
                'message': 'Phone number is required'
            }), 400
            
        success = send_whatsapp_template(
            phone_number=phone,
            template_name=template,
            template_language=language,
            message_text=message_text,
            link_url=link_url,
            image_id=image_id
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Template message sent to {phone}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send template message. Check server logs.'
            }), 400
    except Exception as e:
        logger.exception("Error sending template:")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/check-webhook-subscriptions')
def check_webhook_subscriptions():
    """Check current webhook subscriptions and update if needed."""
    try:
        # Check current subscriptions
        url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/subscribed_apps"
        headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
        
        response = requests.get(url, headers=headers)
        current_subscriptions = response.json()
        
        # Update subscriptions to ensure 'messages' is included
        update_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/subscribed_apps"
        update_data = {
            "field_name": [
                "messages",
                "message_status_updates"
            ]
        }
        
        update_response = requests.post(update_url, headers=headers, json=update_data)
        update_result = update_response.json()
        
        return jsonify({
            "current_subscriptions": current_subscriptions,
            "update_result": update_result
        })
    except Exception as e:
        logger.exception("Error checking subscriptions:")
        return jsonify({"error": str(e)})

# ------------------------------------------------------------------------------
# WhatsApp new template tests
# ------------------------------------------------------------------------------

@app.route('/fetch-templates', methods=['GET'])
def fetch_templates():
    """Fetch templates directly from Meta's Graph API."""
    try:
        # Get WhatsApp Business Account ID from query parameter
        waba_id = request.args.get('waba_id', '539741765897929')  # Use your known WABA ID as the default
        
        # If no WABA ID provided, try to get it from the phone number
        if not waba_id:
            phone_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
            headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
            
            phone_response = requests.get(phone_url, headers=headers)
            if phone_response.status_code != 200:
                return jsonify({
                    "status": "error",
                    "message": f"Error getting phone info: {phone_response.text}"
                }), phone_response.status_code
                
            phone_data = phone_response.json()
            logger.debug(f"Phone data response: {phone_data}")
            
            waba_id = phone_data.get('whatsapp_business_account_id')
            
            if not waba_id:
                return jsonify({
                    "status": "error",
                    "message": "Could not determine WhatsApp Business Account ID from phone info. Please provide it manually via ?waba_id=YOUR_ID"
                }), 400
        
        # Log the WABA ID being used
        logger.info(f"Using WABA ID: {waba_id}")
        
        # Fetch templates from Meta API
        url = f"https://graph.facebook.com/v18.0/{waba_id}/message_templates"
        headers = {
            "Authorization": f"Bearer {META_ACCESS_TOKEN}"
        }
        
        logger.debug(f"Requesting templates from: {url}")
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return jsonify({
                "status": "error",
                "message": f"Error fetching templates: {response.text}"
            }), response.status_code
        
        templates = response.json()
        logger.debug(f"Got templates response: {templates}")
        
        # Process templates to extract useful information
        processed_templates = []
        
        for template in templates.get('data', []):
            components = template.get('components', [])
            
            # Analyze components to determine template capabilities
            has_header = any(comp.get('type') == 'HEADER' for comp in components)
            has_buttons = any(comp.get('type') == 'BUTTONS' for comp in components)
            has_body = any(comp.get('type') == 'BODY' for comp in components)
            has_footer = any(comp.get('type') == 'FOOTER' for comp in components)
            
            # Extract button types if any
            button_types = []
            for comp in components:
                if comp.get('type') == 'BUTTONS':
                    for button in comp.get('buttons', []):
                        button_types.append(button.get('type'))
            
            # Check for header format type
            header_format = None
            for comp in components:
                if comp.get('type') == 'HEADER':
                    header_format = comp.get('format')
            
            # Extract example values for components
            component_params = {}
            for comp in components:
                if comp.get('type') == 'BODY' and 'text' in comp:
                    # Extract placeholders like {{1}} from text
                    import re
                    placeholders = re.findall(r'{{(\d+)}}', comp.get('text', ''))
                    if placeholders:
                        component_params['body'] = [{"placeholder": p} for p in placeholders]
                        
                elif comp.get('type') == 'HEADER' and comp.get('format') != 'TEXT':
                    component_params['header'] = {"format": comp.get('format')}
                    
                elif comp.get('type') == 'BUTTONS':
                    for i, button in enumerate(comp.get('buttons', [])):
                        if button.get('type') == 'URL':
                            if 'buttons' not in component_params:
                                component_params['buttons'] = []
                            component_params['buttons'].append({
                                "index": i,
                                "type": "URL",
                                "url_type": button.get('url_type')
                            })
            
            processed_templates.append({
                "name": template.get('name'),
                "id": template.get('id'),
                "language": template.get('language'),
                "status": template.get('status'),
                "category": template.get('category'),
                "components": {
                    "has_header": has_header,
                    "has_body": has_body,
                    "has_footer": has_footer,
                    "has_buttons": has_buttons,
                    "button_types": button_types,
                    "header_format": header_format
                },
                "component_params": component_params
            })
        
        return jsonify({
            "status": "success",
            "waba_id": waba_id,
            "templates": processed_templates
        })
        
    except Exception as e:
        logger.exception(f"Error fetching templates from Meta API: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/templates-admin')
def templates_admin():
    """Admin page for viewing and testing templates."""
    return render_template('templates_admin.html')

@app.route('/templates-sync')
def templates_sync():
    """Force a sync with WhatsApp templates."""
    try:
        # Get WhatsApp Business Account ID
        phone_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
        headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
        
        phone_response = requests.get(phone_url, headers=headers)
        if phone_response.status_code != 200:
            return jsonify({
                "status": "error",
                "message": f"Could not get WABA ID: {phone_response.text}"
            }), 400
            
        phone_data = phone_response.json()
        waba_id = phone_data.get('whatsapp_business_account_id')
        
        if not waba_id:
            return jsonify({
                "status": "error",
                "message": "Could not determine WhatsApp Business Account ID"
            }), 400
        
        # Fetch templates
        templates_url = f"https://graph.facebook.com/v18.0/{waba_id}/message_templates"
        templates_response = requests.get(templates_url, headers=headers)
        
        if templates_response.status_code != 200:
            return jsonify({
                "status": "error", 
                "message": f"Error fetching templates: {templates_response.text}"
            }), templates_response.status_code
        
        templates_data = templates_response.json()
        
        # Store templates for caching purposes
        with open('templates_cache.json', 'w') as f:
            json.dump(templates_data, f, indent=2)
        
        return jsonify({
            "status": "success",
            "waba_id": waba_id,
            "templates_count": len(templates_data.get('data', [])),
            "templates": templates_data
        })
        
    except Exception as e:
        logger.exception("Error syncing templates:")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/templates-cache')
def templates_cache():
    """Get templates from cache file."""
    try:
        if os.path.exists('templates_cache.json'):
            with open('templates_cache.json', 'r') as f:
                templates_data = json.load(f)
                
            return jsonify({
                "status": "success",
                "source": "cache",
                "waba_id": "539741765897929", 
                "templates": templates_data
            })
        else:
            return jsonify({
                "status": "error",
                "message": "No templates cache found. Please sync templates first."
            }), 404
            
    except Exception as e:
        logger.exception("Error reading templates cache:")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# ------------------------------------------------------------------------------
# WhatsApp Onboarding Routes
# ------------------------------------------------------------------------------
@app.route('/onboard')
def onboard_whatsapp():
    """Page for connecting existing WhatsApp Business account."""
    # Load additional environment variables needed for onboarding
    meta_app_id = os.getenv('META_APP_ID', '')
    meta_config_id = os.getenv('META_CONFIG_ID', '')
    
    return render_template('onboard.html', 
                          meta_app_id=meta_app_id,
                          meta_config_id=meta_config_id)

@app.route('/onboard-callback', methods=['POST'])
def onboard_callback():
    """Handle the callback when WhatsApp Business app onboarding completes."""
    try:
        data = request.json
        logger.debug(f"Received onboarding callback data: {json.dumps(data, indent=2)}")
        
        # Store the callback data for analysis
        with open('last_onboarding_callback.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        # Check if this is a WhatsApp Business App onboarding event
        if data.get('type') == 'WA_EMBEDDED_SIGNUP' and data.get('event') == 'FINISH_WHATSAPP_BUSINESS_APP_ONBOARDING':
            waba_id = data.get('data', {}).get('waba_id')
            phone_number_id = data.get('data', {}).get('phone_number_id', META_PHONE_NUMBER_ID)
            
            logger.info(f"WhatsApp Business App onboarding completed. WABA ID: {waba_id}")
            
            # Store this information (in a real app, you'd save to a database)
            # For now, we'll just write to a file
            onboarding_info = {
                'waba_id': waba_id,
                'phone_number_id': phone_number_id,
                'timestamp': int(time.time())
            }
            with open('onboarding_info.json', 'w') as f:
                json.dump(onboarding_info, f, indent=2)
            
            # Initiate sync processes - start with contacts sync
            try:
                logger.info("Initiating contacts synchronization...")
                response = initiate_contacts_sync(phone_number_id)
                logger.info(f"Contacts sync response: {response}")
            except Exception as e:
                logger.error(f"Error initiating contacts sync: {str(e)}")
            
            # Then initiate message history sync
            try:
                logger.info("Initiating message history synchronization...")
                response = initiate_history_sync(phone_number_id)
                logger.info(f"History sync response: {response}")
            except Exception as e:
                logger.error(f"Error initiating history sync: {str(e)}")
            
            return jsonify({
                'success': True,
                'message': 'WhatsApp Business account connected successfully'
            })
        else:
            logger.warning(f"Received unknown onboarding event: {data.get('event')}")
            return jsonify({
                'success': False,
                'message': 'Unknown onboarding event'
            })
    except Exception as e:
        logger.error(f"Error processing onboarding callback: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

# ------------------------------------------------------------------------------
# Test Routes for Troubleshooting
# ------------------------------------------------------------------------------
@app.route('/test')
def test_route():
    """Simple test route to check if Flask is working."""
    return "This is a test route - Flask is working!"

@app.route('/template-test')
def template_test_tool():
    """Tool to test sending template messages."""
    return render_template('template_test.html')

@app.route('/check-files')
def check_files():
    """Check if template files exist and are accessible."""
    template_dir = os.path.abspath('templates')
    results = {
        "template_dir": template_dir,
        "template_dir_exists": os.path.exists(template_dir),
        "template_dir_is_dir": os.path.isdir(template_dir) if os.path.exists(template_dir) else False,
        "files_in_template_dir": os.listdir(template_dir) if os.path.exists(template_dir) and os.path.isdir(template_dir) else [],
        "index_html_exists": os.path.exists(os.path.join(template_dir, 'index.html')) if os.path.exists(template_dir) else False,
        "onboard_html_exists": os.path.exists(os.path.join(template_dir, 'onboard.html')) if os.path.exists(template_dir) else False,
    }
    return jsonify(results)

@app.route('/privacy')
def privacy_policy():
    """Serve the privacy policy page."""
    return render_template('privacy.html')

@app.route('/webhook-verify', methods=['GET'])
def webhook_verify():
    """Verify webhook configuration with Meta."""
    try:
        # Check if we have proper configuration
        if not META_ACCESS_TOKEN or not META_PHONE_NUMBER_ID:
            return jsonify({
                "status": "error",
                "message": "Missing Meta credentials in environment variables"
            }), 400
            
        # Get details about the phone number
        phone_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}"
        headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}
        
        phone_response = requests.get(phone_url, headers=headers)
        phone_data = phone_response.json()
        
        # Check if webhook configuration exists
        webhook_config = phone_data.get('webhook_configuration', {})
        webhook_url = webhook_config.get('application', 'Not configured')
        
        # Check webhook status by making a test call to the webhook
        webhook_status = "Unknown"
        if webhook_url != 'Not configured':
            try:
                # Ping the webhook URL
                webhook_response = requests.get(webhook_url, timeout=5)
                webhook_status = f"Status {webhook_response.status_code}"
            except Exception as e:
                webhook_status = f"Error: {str(e)}"
        
        # Get webhook fields we're subscribed to
        fields_url = f"https://graph.facebook.com/v18.0/{META_PHONE_NUMBER_ID}/subscribed_apps"
        fields_response = requests.get(fields_url, headers=headers)
        fields_data = fields_response.json()
        
        # Get business verification status from WABA
        waba_id = phone_data.get('whatsapp_business_account_id')
        waba_data = {}
        if waba_id:
            waba_url = f"https://graph.facebook.com/v18.0/{waba_id}"
            waba_response = requests.get(waba_url, headers=headers)
            waba_data = waba_response.json()
            
        return jsonify({
            "status": "success",
            "phone_number_info": phone_data,
            "webhook_url": webhook_url,
            "webhook_status": webhook_status,
            "subscribed_fields": fields_data.get('data', []),
            "waba_info": waba_data
        })
    except Exception as e:
        logger.exception("Error verifying webhook:")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/webhook-console')
def webhook_console():
    """Interactive webhook testing console."""
    return render_template('webhook_console.html')
    
# ------------------------------------------------------------------------------
# Main Entry
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    
    print("\n=== WhatsApp Message Sender MVP ===")
    print(f"Server running on: http://0.0.0.0:3000")
    print(f"META_VERIFY_TOKEN: {META_VERIFY_TOKEN}")
    print(f"META_PHONE_NUMBER_ID configured: {'Yes' if META_PHONE_NUMBER_ID else 'No'}")
    print(f"META_ACCESS_TOKEN configured: {'Yes' if META_ACCESS_TOKEN else 'No'}")
    print(f"Private key path: {PRIVATE_KEY_PATH}")
    print(f"Private key exists: {'Yes' if os.path.exists(PRIVATE_KEY_PATH) else 'No - WILL CAUSE ERRORS'}")
    print(f"Firebase initialized: {'Yes' if firebase.initialized else 'No - Backups disabled'}")
    print("===================================\n")
    
    # Initialize app files
    initialize_app_files()
    
    # Initialize private key from environment variable if available
    initialize_private_key()
    
    # Use the PORT environment variable provided by Render
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=False)