import pytest
from flask_jwt_extended import JWTManager


@pytest.fixture()
def make_header():
    def _make_header(
        authorization: str = None,
        content_type: str = "application/json",
        accept: str = "application/json",
    ):

        return {
            "Authorization": authorization,
            "Content-Type": content_type,
            "Accept": accept,
        }

    return _make_header


@pytest.fixture()
def client(app):
    app.testing = True
    return app.test_client()


@pytest.fixture()
def test_request_context(app):
    return app.test_request_context()


@pytest.fixture()
def jwt_manager(app):
    return JWTManager(app)
