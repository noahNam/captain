from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import JWTManager

from app.extensions.cache.cache import RedisClient
from core.domains.oauth.enum.oauth_enum import (
    OAuthKakaoEnum,
    ProviderEnum,
    OAuthNaverEnum,
    OAuthGoogleEnum,
)

jwt = JWTManager()
oauth = OAuth()
redis = RedisClient()

oauth.register(
    name=ProviderEnum.KAKAO.value,
    client_id=OAuthKakaoEnum.KAKAO_CLIENT_ID.value,
    client_secret=OAuthKakaoEnum.KAKAO_CLIENT_SECRET.value,
    api_base_url=OAuthKakaoEnum.AUTH_BASE_URL,
    authorize_url=OAuthKakaoEnum.AUTH_BASE_URL.value
    + OAuthKakaoEnum.AUTHORIZE_END_POINT.value,
    authorize_params=None,
    access_token_url=OAuthKakaoEnum.AUTH_BASE_URL.value
    + OAuthKakaoEnum.ACCESS_TOKEN_END_POINT.value,
    access_token_params=None,
)

oauth.register(
    name=ProviderEnum.NAVER.value,
    client_id=OAuthNaverEnum.NAVER_CLIENT_ID.value,
    client_secret=OAuthNaverEnum.NAVER_CLIENT_SECRET.value,
    api_base_url=OAuthNaverEnum.AUTH_BASE_URL,
    authorize_url=OAuthNaverEnum.AUTH_BASE_URL.value
    + OAuthNaverEnum.AUTHORIZE_END_POINT.value,
    authorize_params=None,
    access_token_url=OAuthNaverEnum.AUTH_BASE_URL.value
    + OAuthNaverEnum.ACCESS_TOKEN_END_POINT.value,
    access_token_params=None,
)

oauth.register(
    name=ProviderEnum.GOOGLE.value,
    client_id=OAuthGoogleEnum.GOOGLE_CLIENT_ID.value,
    client_secret=OAuthGoogleEnum.GOOGLE_CLIENT_SECRET.value,
    access_token_url=OAuthGoogleEnum.TOKEN_URL.value,
    access_token_params=None,
    authorize_url=OAuthGoogleEnum.AUTH_URL.value,
    authorize_params=None,
    api_base_url=OAuthGoogleEnum.API_BASE_URL.value,
    client_kwargs={"scope": "openid"}
)
