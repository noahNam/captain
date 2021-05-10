import os
from typing import Optional, Any

import requests

from core.domains.oauth.enum.oauth_enum import OAuthKakaoEnum


def request_oauth_access_token_to_kakao(
        code: Optional[any]) -> Any:
    return requests.post(
        url=OAuthKakaoEnum.AUTH_BASE_URL.value + OAuthKakaoEnum.ACCESS_TOKEN_END_POINT.value,
        headers=OAuthKakaoEnum.REQUEST_DEFAULT_HEADER.value,
        data={
            "grant_type": OAuthKakaoEnum.GRANT_TYPE.value,
            "client_id": os.getenv("KAKAO_CLIENT_ID"),
            "redirect_uri": OAuthKakaoEnum.REDIRECT_URL.value,
            "code": code,
            "client_secret": os.getenv("KAKAO_CLIENT_SECRET"),
        },
    )


def get_kakao_user_info(token_info) -> Any:
    return requests.get(
        url=OAuthKakaoEnum.API_BASE_URL.value + OAuthKakaoEnum.USER_INFO_END_POINT.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
            "Authorization": "Bearer " + token_info.json().get("access_token")
        },
    )
