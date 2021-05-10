import pytest
from flask import url_for
from flask.ctx import RequestContext
from flask.testing import FlaskClient

from app.extensions.utils.oauth_helper import request_oauth_access_token_to_kakao
from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto
from core.exception import InvalidRequestException


def test_when_request_with_not_parameter_then_raise_validation_error(
        client: FlaskClient, test_request_context: RequestContext):
    """
        given : Nothing
        when : [GET] /api/captain/v1/oauth
        then : raise InvalidRequestException
    """
    with pytest.raises(InvalidRequestException):
        with test_request_context:
            client.get(url_for("api.request_oauth_to_third_party"))


def test_when_request_with_kakao_then_redirect_to_fetch_token_url(
        client: FlaskClient, test_request_context: RequestContext):
    """
        given : GetOAuthDto(provider="kakao")
        when : [GET] /api/captain/v1/oauth?provider=kakao
        then : redirect to kakao authorize request url
    """
    dto = GetOAuthProviderDto(provider="kakao")

    with test_request_context:
        response = client.get(
            url_for("api.request_oauth_to_third_party", provider=dto.provider)
        )

    assert response.status_code == 302


def test_when_request_with_wrong_provider_then_raise_validation_error(
        client: FlaskClient, test_request_context: RequestContext):
    """
        given : wrong provider value (not in ["naver" or "kakao"])
        when : [GET] /api/captain/v1/oauth?provider="mooyaho"
        then : raise InvalidRequestException
    """
    dto = GetOAuthProviderDto(provider="mooyaho")
    with pytest.raises(InvalidRequestException):
        with test_request_context:
            client.get(url_for("api.request_oauth_to_third_party", provider=dto.provider))


def test_when_success_kakao_redirect_and_failed_token_request_then_response_400():
    """
        given : authorization_code = None
        when : [POST] /api/captain/v1/oauth/kakao
        then : response
    """
    authorization_code = None
    response = request_oauth_access_token_to_kakao(authorization_code)

    assert response.status_code == 400

# mocking -> True 처리 예정
# def test_when_success_kakao_redirect_and_success_token_request_then_response_200():
#     """
#         given : authorization_code = "correct_code"
#         when : [POST] /api/captain/v1/oauth/kakao
#         then : response
#     """
#     authorization_code = "yKxyFyqwgoWBR0VWj5fP0SRgcX-ysECUJ0zKfPrYseAWz-VK75KqHNiHw_h4o-YU2io9qQo9dJcAAAF5PWZeYg"
#     response = request_oauth_access_token_to_kakao(authorization_code)
#
#     assert response.status_code == 200
