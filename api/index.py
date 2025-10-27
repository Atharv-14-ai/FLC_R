# api/index.py
from vercel_wsgi import make_app
from app import app

# Wrap your Flask WSGI app for Vercel
app = make_app(app)
