from app.http.requests.view.oauth.v1.oauth_request import GetOAuthRequest, CreateUser


def test_when_valid_request_with_naver_then_success():
    """
    API route: [GET] /api/captain/v1/oauth
    parameter: 'kakao' or 'naver' -> success
    """
    result = GetOAuthRequest(provider="naver").validate_request_and_make_dto()
    assert result.provider == "naver"


def test_when_valid_request_with_kakao_then_success():
    result = GetOAuthRequest(provider="kakao").validate_request_and_make_dto()
    assert result.provider == "kakao"


def test_when_invalid_request_then_fail():
    result = GetOAuthRequest(provider="hawaii").validate_request_and_make_dto()

    assert result is False


def test_when_valid_input_user_info_then_success():
    result = CreateUser(provider="kakao", provider_id=12345).validate_request_and_make_dto()
    assert result.provider == "kakao"
    assert result.provider_id == 12345


def test_when_invalid_input_user_info_then_fail():
    result = CreateUser(provider="not_provider", provider_id="not_int").validate_request_and_make_dto()
    assert result is False
