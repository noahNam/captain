import os


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


class ProductionConfig(Config):
    os.environ["FLASK_ENV"] = "production"


config = dict(
    default=LocalConfig,
    local=LocalConfig,
    testing=TestConfig,
    dev=DevelopmentConfig,
    prod=ProductionConfig,
)
