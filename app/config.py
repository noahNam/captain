import os

from dotenv import load_dotenv, find_dotenv


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "auckland"
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "hawaii"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_ECHO = False
    DEBUG = False


class LocalConfig(Config):
    os.environ["FLASK_ENV"] = "local"
    SQLALCHEMY_ECHO = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://postgres:1234@localhost:5432/captain"


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = (
            os.environ.get("TEST_DATABASE_URL") or "sqlite:///:memory:"
    )

    WTF_CSRF_ENABLED = False


class DevelopmentConfig(Config):
    os.environ["FLASK_ENV"] = "development"
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URL") or "sqlite:///:memory:"

    # python-dotenv for OAuth secret_key
    load_dotenv(find_dotenv())

    # OAuth 2.0 Provider config
    KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID")
    KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET")


class ProductionConfig(Config):
    os.environ["FLASK_ENV"] = "production"


config = dict(
    default=LocalConfig,
    local=LocalConfig,
    testing=TestConfig,
    dev=DevelopmentConfig,
    prod=ProductionConfig,
)
