# config.py
import os
import logging
from dotenv import load_dotenv

load_dotenv()  # load environment variables from .env

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# ------------------------------------------------------------------------------
# Environment Variables
# ------------------------------------------------------------------------------
META_VERIFY_TOKEN = os.getenv('META_VERIFY_TOKEN', 'happy')
META_ACCESS_TOKEN = os.getenv('META_ACCESS_TOKEN', '')
META_PHONE_NUMBER_ID = os.getenv('META_PHONE_NUMBER_ID', '')

private_key_path = os.getenv('PRIVATE_KEY_PATH', 'private_key.pem')
private_key_password = os.getenv('PRIVATE_KEY_PASSWORD', '')

UPLOAD_FOLDER = 'uploads'
MESSAGES_FILE = 'message_templates.json'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# ------------------------------------------------------------------------------
# Survey Types
# ------------------------------------------------------------------------------
SURVEY_TYPES = {
    'initial_rsvp': {
        'name': 'Initial RSVP Survey',
        'flow': ['invite', 'guest_count', 'allergies', 'shuttle', 'thank_you_attending']
    },
    'reminder': {
        'name': 'Reminder for Non-Respondents',
        'flow': ['reminder']
    },
    'event_details': {
        'name': 'Event Details for Attendees',
        'flow': ['transport_choice', 'location_details']
    },
    'post_event': {
        'name': 'Post-Event Thank You',
        'flow': ['thank_you_attended']
    }
}

# ------------------------------------------------------------------------------
# Meta Template Mapping
# ------------------------------------------------------------------------------
META_TEMPLATES = {
    'invite': 'event_invitation',
    'guest_count': 'guest_count_query',
    'allergies': 'allergy_query',
    'shuttle': 'shuttle_query',
    'thank_you_attending': 'thank_you_confirm',
    'thank_you_declined': 'thank_you_decline',
    'reminder': 'reminder_message',
    'transport_choice': 'transport_query',
    'location_details': 'location_details',
    'thank_you_attended': 'thank_you_attended'
}
