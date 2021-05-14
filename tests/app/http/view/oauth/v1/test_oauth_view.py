from http import HTTPStatus
from unittest.mock import patch, MagicMock

from flask import url_for, Response
from flask.ctx import RequestContext
from flask.testing import FlaskClient
from sqlalchemy.orm import scoped_session

from app.extensions.utils.oauth_helper import request_oauth_access_token_to_kakao, get_kakao_user_info
from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.use_case_output import FailureType


class MockResponse:
    def __init__(self, json_data, status_code, raise_for_status=None):
        self._json_data = json_data
        self._status_code = status_code
        self._raise_for_status = raise_for_status

    def json(self):
        return self._json_data

    def raise_for_status(self):
        # None mean success
        return self._raise_for_status


def test_when_request_with_not_parameter_then_raise_validation_error(
        client: FlaskClient, test_request_context: RequestContext):
    """
        given : Nothing
        when : [GET] /api/captain/v1/oauth
        then : raise InvalidRequestException
    """
    with test_request_context:
        response = client.get(url_for("api.request_oauth_to_third_party"))

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json()["type"] == FailureType.INVALID_REQUEST_ERROR


def test_when_request_oauth_to_kakao_then_redirect_to_fetch_token_url(
        client: FlaskClient, test_request_context: RequestContext):
    """
        given : GetOAuthDto(provider="kakao")
        when : [GET] /api/captain/v1/oauth?provider=kakao
        then : redirect to kakao authorize request url
    """
    with test_request_context:
        response = client.get(
            url_for("api.request_oauth_to_third_party", provider=ProviderEnum.KAKAO.value)
        )

    assert response.status_code == 302
    assert b"https://kauth.kakao.com/oauth/authorize" in response.data
    assert b"client_id" in response.data
    assert b"redirect" in response.data
    assert b"response_type=code" in response.data
    assert b"state" in response.data


@patch("app.http.view.oauth.kakao.authorize_redirect")
def test_mock_oauth_request_to_kakao_when_success(
        mock_request: MagicMock,
        client: FlaskClient,
        test_request_context: RequestContext):
    """
        <mocking test>
            when : [GET] /api/captain/v1/oauth?provider=kakao
            then : success
    """
    mock_request.return_value = Response()
    mock_request.return_value.status_code = 302
    mock_request.return_value.data = b"https://kauth.kakao.com/oauth/authorize...something"

    with test_request_context:
        response = client.get(
            url_for("api.request_oauth_to_third_party", provider=ProviderEnum.KAKAO.value)
        )

    assert response.status_code == mock_request.return_value.status_code
    assert response.data == mock_request.return_value.data
    assert mock_request.called is True


def test_when_request_with_wrong_provider_then_raise_validation_error(
        client: FlaskClient, test_request_context: RequestContext):
    """
        given : wrong provider value (not in ["naver" or "kakao"])
        when : [GET] /api/captain/v1/oauth?provider="mooyaho"
        then : raise InvalidRequestException
    """
    dto = GetOAuthProviderDto(provider="mooyaho")
    with test_request_context:
        response = client.get(url_for("api.request_oauth_to_third_party", provider=dto.provider))

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json()["type"] == FailureType.INVALID_REQUEST_ERROR


def test_when_success_kakao_redirect_and_failed_token_request_then_response_400():
    """
        given : authorization_code = None
        when : [POST] /api/captain/v1/oauth/kakao
        then : response
    """
    authorization_code = None
    response = request_oauth_access_token_to_kakao(authorization_code)

    assert response.status_code == 400


@patch("requests.post")
def test_mock_request_access_token_to_kakao(mock_post):
    """
        <mocking test>
            인가 서버 -> Access_Token 요청
    """
    mock_contents = {
        "token_type": "bearer",
        "access_token": "some token string",
        "expires_in": 12345,
        "refresh_token": "some token string",
        "refresh_token_expires_in": 67890,
    }
    mock_post.return_value.status_code = 201
    mock_post.return_value.data = mock_contents

    assert request_oauth_access_token_to_kakao(code="code").status_code == mock_post.return_value.status_code
    assert "access_token" in mock_post.return_value.data
    assert mock_post.called is True


@patch("requests.get")
def test_mock_request_get_kakao_user_info(mock_get):
    """
        <mocking test>
            자원 서버 -> kakao ID 요청
    """
    mock_contents = {
        "id": 123456
    }

    mock_token = {"access_token": "something awesome token"}

    mock_get.return_value.data = mock_contents
    mock_get.return_value.status_code = 200

    assert get_kakao_user_info(mock_token).status_code == mock_get.return_value.status_code
    assert get_kakao_user_info(mock_token).data == mock_get.return_value.data
    assert mock_get.called is True


def test_when_redirect_kakao_and_success_token_request_then_success(
        session: scoped_session, client: FlaskClient, test_request_context: RequestContext):
    """
        given : OAuth tokens = "some token value from kakao" -> mocking
                provider_id from kakao = int -> mocking
        when : [POST] /api/captain/v1/oauth/kakao, code="some authorization code"
        then : return JWT
    """

    mock_token_info = {
        "token_type": "bearer",
        "access_token": "some token string",
        "expires_in": 12345,
        "refresh_token": "some token string",
        "refresh_token_expires_in": 67890,
    }

    mock_kakao_id = {
        "id": 123456
    }

    with patch("app.http.view.oauth.kakao.authorize_redirect") as mock_redirect:
        mock_redirect.return_value = Response()
        mock_redirect.return_value.status_code = 302
        mock_redirect.return_value.data = b"https://kauth.kakao.com/oauth/authorize...something"
        with test_request_context:
            redirect_response = client.get(
                url_for("api.request_oauth_to_third_party", provider=ProviderEnum.KAKAO.value)
            )
            with patch("requests.post") as mock_post:
                mock_post.return_value = MockResponse(json_data=mock_token_info, status_code=201)
                with patch("requests.get") as mock_get:
                    mock_get.return_value = MockResponse(json_data=mock_kakao_id, status_code=200)
                    with test_request_context:
                        response = client.get(
                            url_for("api.fetch_kakao_access_token", code="code")
                        )

    data = response.get_json().get("data")

    assert redirect_response.status_code == mock_redirect.return_value.status_code
    assert response.status_code == 200
    assert isinstance(data["token_info"]["access_token"], str)
    assert isinstance(data["token_info"]["refresh_token"], str)
    assert mock_redirect.called is True
    assert mock_get.called is True
    assert mock_post.called is True
