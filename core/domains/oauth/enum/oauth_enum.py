from enum import Enum


class OAuthBaseHostEnum(Enum):
    REDIRECT_HOST = "https://apartalk.com/"


class OAuthKakaoEnum(Enum):
    # Kakao Secret_key for access kakao api
    KAKAO_CLIENT_ID = "685d9d3691ad88dac84b6f06066c9e91"
    KAKAO_CLIENT_SECRET = "waB8DtEHj1VMgMso8H0d9HwTXmSoat3a"

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
    NAVER_CLIENT_ID = "Xs3HQd3K26WlaLe9IWsH"
    NAVER_CLIENT_SECRET = "UARktCnNGd"

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
