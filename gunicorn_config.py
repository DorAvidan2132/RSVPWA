import os

bind = f"0.0.0.0:{os.environ.get('PORT', '3000')}"
workers = 1
threads = 2
timeout = 120