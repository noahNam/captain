from enum import Enum


class OAuthKakaoEnum(Enum):
    AUTH_BASE_URL = "https://kauth.kakao.com"
    API_BASE_URL = "https://kapi.kakao.com"
    AUTHORIZE_END_POINT = "/oauth/authorize"
    ACCESS_TOKEN_END_POINT = "/oauth/token"
    USER_INFO_END_POINT = "/v2/user/me"
    # with app.app_context():
    #     REDIRECT_URL = request.host_url + url_for("api.fetch_kakao_access_token")
    REDIRECT_URL = "http://127.0.0.1:5000" + "/api/captain/v1/oauth/kakao"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }
