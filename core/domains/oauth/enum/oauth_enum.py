from enum import Enum


class OAuthKakaoEnum(Enum):
    # Kakao Secret_key for access kakao api
    KAKAO_CLIENT_ID = "bd800185a84b3e7b269cf97845cccaec"
    KAKAO_CLIENT_SECRET = "oyCAZ7f91qhzPkCn4ocUfuiaQQXjpkjr"

    AUTH_BASE_URL = "https://kauth.kakao.com"
    API_BASE_URL = "https://kapi.kakao.com"
    AUTHORIZE_END_POINT = "/oauth/authorize"
    ACCESS_TOKEN_END_POINT = "/oauth/token"
    USER_INFO_END_POINT = "/v2/user/me"
    REDIRECT_URL = "http://127.0.0.1:5000" + "/api/captain/v1/oauth/kakao"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }


class ProviderEnum(Enum):
    KAKAO = "kakao"
    NAVER = "naver"
