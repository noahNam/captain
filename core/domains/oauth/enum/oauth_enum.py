import os
from enum import Enum


class OAuthBaseHostEnum(Enum):
    OAUTH_REDIRECT_HOST = os.environ.get("OAUTH_REDIRECT_HOST") or ""


class OAuthKakaoEnum(Enum):
    # Kakao Secret_key for access kakao api
    KAKAO_CLIENT_ID = "685d9d3691ad88dac84b6f06066c9e91"
    KAKAO_CLIENT_SECRET = "waB8DtEHj1VMgMso8H0d9HwTXmSoat3a"

    AUTH_BASE_URL = "https://kauth.kakao.com"
    API_BASE_URL = "https://kapi.kakao.com"
    AUTHORIZE_END_POINT = "/oauth/authorize"
    ACCESS_TOKEN_END_POINT = "/oauth/token"
    USER_INFO_END_POINT = "/v2/user/me"
    REDIRECT_PATH = "api/captain/v1/oauth/kakao/web"
    ACCESS_TOKEN_VALIDATION_END_POINT = "/v1/user/access_token_info"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }


class ProviderEnum(Enum):
    KAKAO = "kakao"
    NAVER = "naver"
    GOOGLE = "google"


class OAuthNaverEnum(Enum):
    NAVER_CLIENT_ID = "Xs3HQd3K26WlaLe9IWsH"
    NAVER_CLIENT_SECRET = "UARktCnNGd"

    AUTH_BASE_URL = "https://nid.naver.com"
    API_BASE_URL = "https://openapi.naver.com"
    AUTHORIZE_END_POINT = "/oauth2.0/authorize"
    ACCESS_TOKEN_END_POINT = "/oauth2.0/token"
    REDIRECT_PATH = "api/captain/v1/oauth/naver/web"
    USER_INFO_END_POINT = "/v1/nid/me"
    ACCESS_TOKEN_VALIDATION_END_POINT = "/v1/nid/verify"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }


class OAuthGoogleEnum(Enum):
    GOOGLE_CLIENT_ID = (
        "154375598296-6gnkc9ds4tbflnqi45q0pht5cjb1o9b5.apps.googleusercontent.com"
    )
    GOOGLE_CLIENT_SECRET = "J0PxwoJ7xMcSHXflLY8sQm_t"
    PROJECT_ID = "toadhome-oauth"

    AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    API_BASE_URL = "https://oauth2.googleapis.com"
    USER_INFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
    AUTH_PROVIDER_X509_CERT_URI = "https://www.googleapis.com/oauth2/v1/certs"
    REDIRECT_PATH = "api/captain/v1/oauth/google/web"

    GRANT_TYPE = "authorization_code"
    REQUEST_DEFAULT_HEADER = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cache-Control": "no-cache",
    }
