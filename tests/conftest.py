import os

import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import scoped_session

from app import create_app
from app.extensions.database import db as _db


@pytest.fixture(scope="session")
def app() -> Flask:
    app = create_app("testing")
    app_context = app.app_context()
    app_context.push()

    yield app

    app_context.pop()


@pytest.fixture(scope="function")
def db(app: Flask):
    database_url = app.config["SQLALCHEMY_DATABASE_URI"]

    _is_local_db_used(database_url)

    _db.app = app

    if is_sqlite_used(database_url):
        _db.create_all()
        yield _db
        _db.drop_all()
    else:
        yield _db


def is_sqlite_used(database_url: str):
    if ":memory:" in database_url:
        return True
    return False


def _is_local_db_used(database_url: str):
    """
    local db를 사용하면 memory db 삭제
    """
    if ":memory:" not in database_url:
        if os.path.exists(database_url.split("sqlite:///")[-1]):  # :memory:
            os.unlink(database_url.split("sqlite:///")[-1])


@pytest.fixture(scope="function")
def session(db: SQLAlchemy) -> scoped_session:
    """
    Creates a new persistence session for a tests.
    http://alexmic.net/flask-sqlalchemy-pytest/
    """

    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)

    db.session = session

    yield db.session

    transaction.rollback()
    connection.close()
    session.remove()
