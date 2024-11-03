import os
class Config:
    # Automatically generate a random secret key if one is not set
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)

    # PostgreSQL connection string
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:dilip@localhost/pmdcs'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
