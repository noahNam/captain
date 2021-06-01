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
    REDIRECT_PATH = "api/captain/v1/oauth/kakao"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }


class ProviderEnum(Enum):
    KAKAO = "kakao"
    NAVER = "naver"


class OAuthNaverEnum(Enum):
    NAVER_CLIENT_ID = "vThAON6VRNy5wdwFXVez"
    NAVER_CLIENT_SECRET = "iNBqMV6f3b"

    AUTH_BASE_URL = "https://nid.naver.com"
    API_BASE_URL = "https://openapi.naver.com"
    AUTHORIZE_END_POINT = "/oauth2.0/authorize"
    ACCESS_TOKEN_END_POINT = "/oauth2.0/token"
    REDIRECT_PATH = "api/captain/v1/oauth/naver"
    USER_INFO_END_POINT = "/v1/nid/me"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }
