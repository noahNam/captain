import os
from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import JWTManager

from core.domains.oauth.enum.oauth_enum import OAuthKakaoEnum

jwt = JWTManager()
oauth = OAuth()

oauth.register(
    name="kakao",
    client_id=os.getenv("KAKAO_CLIENT_ID"),
    client_secret=os.getenv("KAKAO_CLIENT_SECRET"),
    api_base_url=OAuthKakaoEnum.AUTH_BASE_URL,
    authorize_url=OAuthKakaoEnum.AUTH_BASE_URL.value + OAuthKakaoEnum.AUTHORIZE_END_POINT.value,
    authorize_params=None,
    access_token_url=OAuthKakaoEnum.AUTH_BASE_URL.value + OAuthKakaoEnum.ACCESS_TOKEN_END_POINT.value,
    access_token_params=None,
)
