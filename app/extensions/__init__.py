import os

from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import JWTManager

from app.extensions.utils.oauth_helper import KAKAO_API_BASE_URL, KAKAO_AUTHORIZE_END_POINT, \
    KAKAO_GET_ACCESS_TOKEN_END_POINT, GRANT_TYPE, KAKAO_REDIRECT_URL

jwt = JWTManager()
oauth = OAuth()

oauth.register(
    name="kakao",
    client_id=os.getenv("KAKAO_CLIENT_ID"),
    client_secret=os.getenv("KAKAO_CLIENT_SECRET"),
    api_base_url=KAKAO_API_BASE_URL,
    authorize_url=KAKAO_API_BASE_URL + KAKAO_AUTHORIZE_END_POINT,
    authorize_params=None,
    access_token_url=KAKAO_API_BASE_URL + KAKAO_GET_ACCESS_TOKEN_END_POINT,
    access_token_params=None,
)
