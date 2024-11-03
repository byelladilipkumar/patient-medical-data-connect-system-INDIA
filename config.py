import os
class Config:
    # Automatically generate a random secret key if one is not set
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))

    # PostgreSQL connection string
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL',"postgresql://default:9CtJML4fvQhB@ep-winter-truth-a4ygmkt9.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
