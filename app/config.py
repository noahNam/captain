import datetime
import os
from urllib.parse import quote as urlquote


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "auckland"
    REDIS_URL = os.environ.get("REDIS_URL") or "redis://localhost:6379"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_ECHO = False
    DEBUG = False

    # JWT Config
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=120)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(minutes=5)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "hawaii"


class LocalConfig(Config):
    os.environ["FLASK_ENV"] = "local"
    SENTRY_ENVIRONMENT = "local"
    SQLALCHEMY_ECHO = True
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = (
        "postgresql+psycopg2://captain:!Dkvkxhr117@localhost:5433/captain"
    )

    # Prod migrate
    # SQLALCHEMY_DATABASE_URI = (
    #     f"postgresql+psycopg2://toadhome_captain:%s@localhost:5432/captain"
    #     % urlquote("password")
    # )


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("TEST_DATABASE_URL") or "sqlite:///:memory:"
    )

    WTF_CSRF_ENABLED = False


class DevelopmentConfig(Config):
    os.environ["FLASK_ENV"] = "development"
    SENTRY_ENVIRONMENT = "development"
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URL") or "sqlite:///:memory:"
    SENTRY_KEY = os.environ.get("SENTRY_KEY")


class ProductionConfig(Config):
    os.environ["FLASK_ENV"] = "production"
    SENTRY_ENVIRONMENT = "production"
    SENTRY_KEY = os.environ.get("SENTRY_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("PROD_DATABASE_URL")
    REDIS_NODE_HOST_1 = os.environ.get("REDIS_NODE_HOST_1")
    REDIS_NODE_HOST_2 = os.environ.get("REDIS_NODE_HOST_2")


config = dict(
    default=LocalConfig,
    local=LocalConfig,
    testing=TestConfig,
    development=DevelopmentConfig,
    prod=ProductionConfig,
)
