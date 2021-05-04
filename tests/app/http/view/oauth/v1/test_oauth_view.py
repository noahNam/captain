from flask import url_for
from flask.ctx import RequestContext
from flask.testing import FlaskClient

from app.extensions import KAKAO_AUTHORIZE_END_POINT, KAKAO_API_BASE_URL
from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto


def test_when_request_with_kakao_then_redirect_to_fetch_token_url(
        client: FlaskClient, test_request_context: RequestContext):
    """
    given : GetOAuthDto(provider="kakao")
    when : [GET] /api/captain/v1/oauth?provider=kakao
    then : redirect to kakao authorize request url
    """
    dto = GetOAuthProviderDto(provider="kakao")
    auth_kakao_url = KAKAO_API_BASE_URL + KAKAO_AUTHORIZE_END_POINT

    with test_request_context:
        response = client.get(
            url_for("api.request_oauth_to_third_party", provider=dto.provider)
        )

    assert response.status_code == 302
    assert auth_kakao_url in str(response.data)


def test_when_request_with_wrong_provider_then_response_400(
        client: FlaskClient, test_request_context: RequestContext):
    """
    given : wrong provider value (not in ["naver" or "kakao"])
    when : [GET] /api/captain/v1/oauth?provider="mooyaho"
    then : response 400
    """
    dto = GetOAuthProviderDto(provider="mooyaho")

    with test_request_context:
        response = client.get(
            url_for("api.request_oauth_to_third_party", provider=dto.provider)
        )

    assert response.status_code == 400
