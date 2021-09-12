from typing import Optional, Any

import requests
from flask import request

from core.domains.oauth.enum.oauth_enum import (
    OAuthKakaoEnum,
    OAuthNaverEnum,
    OAuthBaseHostEnum,
    OAuthGoogleEnum,
    OAuthAppleEnum,
)


def request_oauth_access_token_to_kakao(code: Optional[any]) -> Any:
    host_url = (
        OAuthBaseHostEnum.OAUTH_REDIRECT_HOST.value
        if request.environ.get("HTTP_X_REAL_IP", request.remote_addr) != "127.0.0.1"
        else request.host_url
    )
    return requests.post(
        url=OAuthKakaoEnum.AUTH_BASE_URL.value
        + OAuthKakaoEnum.ACCESS_TOKEN_END_POINT.value,
        headers=OAuthKakaoEnum.REQUEST_DEFAULT_HEADER.value,
        data={
            "grant_type": OAuthKakaoEnum.GRANT_TYPE.value,
            "client_id": OAuthKakaoEnum.KAKAO_CLIENT_ID.value,
            "redirect_uri": host_url + OAuthKakaoEnum.REDIRECT_PATH.value,
            "code": code,
            "client_secret": OAuthKakaoEnum.KAKAO_CLIENT_SECRET.value,
        },
    )


def get_kakao_user_info(token_info) -> Any:
    return requests.get(
        url=OAuthKakaoEnum.API_BASE_URL.value
        + OAuthKakaoEnum.USER_INFO_END_POINT.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
            "Authorization": "Bearer " + token_info.get("access_token"),
        },
    )


def request_oauth_access_token_to_naver(code: Optional[any]) -> Any:
    host_url = (
        OAuthBaseHostEnum.OAUTH_REDIRECT_HOST.value
        if request.environ.get("HTTP_X_REAL_IP", request.remote_addr) != "127.0.0.1"
        else request.host_url
    )
    return requests.post(
        url=OAuthNaverEnum.AUTH_BASE_URL.value
        + OAuthNaverEnum.ACCESS_TOKEN_END_POINT.value,
        headers=OAuthNaverEnum.REQUEST_DEFAULT_HEADER.value,
        data={
            "grant_type": OAuthNaverEnum.GRANT_TYPE.value,
            "client_id": OAuthNaverEnum.NAVER_CLIENT_ID.value,
            "redirect_uri": host_url + OAuthNaverEnum.REDIRECT_PATH.value,
            "code": code,
            "client_secret": OAuthNaverEnum.NAVER_CLIENT_SECRET.value,
        },
    )


def get_naver_user_info(token_info) -> Any:
    return requests.get(
        url=OAuthNaverEnum.API_BASE_URL.value
        + OAuthNaverEnum.USER_INFO_END_POINT.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
            "Authorization": "Bearer " + token_info.get("access_token"),
        },
    )


def request_validation_to_kakao(access_token) -> Any:
    return requests.get(
        url=OAuthKakaoEnum.API_BASE_URL.value
        + OAuthKakaoEnum.ACCESS_TOKEN_VALIDATION_END_POINT.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
            "Authorization": "Bearer " + access_token,
        },
    )


def request_validation_to_naver(access_token) -> Any:
    return requests.get(
        url=OAuthNaverEnum.API_BASE_URL.value
        + OAuthNaverEnum.ACCESS_TOKEN_VALIDATION_END_POINT.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
            "Authorization": "Bearer " + access_token,
        },
    )


def request_oauth_access_token_to_google(code: Optional[any]) -> Any:
    host_url = (
        OAuthBaseHostEnum.OAUTH_REDIRECT_HOST.value
        if request.environ.get("HTTP_X_REAL_IP", request.remote_addr) != "127.0.0.1"
        else request.host_url
    )
    return requests.post(
        url=OAuthGoogleEnum.TOKEN_URL.value,
        headers=OAuthGoogleEnum.REQUEST_DEFAULT_HEADER.value,
        data={
            "client_id": OAuthGoogleEnum.GOOGLE_CLIENT_ID.value,
            "client_secret": OAuthGoogleEnum.GOOGLE_CLIENT_SECRET.value,
            "redirect_uri": host_url + OAuthGoogleEnum.REDIRECT_PATH.value,
            "code": code,
            "grant_type": OAuthGoogleEnum.GRANT_TYPE.value,
        },
    )


def get_google_user_info(token_info) -> Any:
    return requests.get(
        url=OAuthGoogleEnum.USER_INFO_URL.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
            "Authorization": "Bearer " + token_info.get("access_token"),
        },
    )


def get_apple_auth_keys() -> Any:
    return requests.get(
        url=OAuthAppleEnum.AUTH_KEYS_URL.value,
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Cache-Control": "no-cache",
        },
    )
