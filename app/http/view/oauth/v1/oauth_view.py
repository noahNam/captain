from http import HTTPStatus
from typing import Any

from flasgger import swag_from
from flask import request, jsonify, Response

from app import oauth
from app.http.responses import failure_response
from core.domains.oauth.enum.oauth_enum import (
    OAuthKakaoEnum,
    ProviderEnum,
    OAuthNaverEnum,
    OAuthBaseHostEnum,
    OAuthGoogleEnum,
)
from app.extensions.utils.oauth_helper import (
    request_oauth_access_token_to_kakao,
    get_kakao_user_info,
    request_oauth_access_token_to_naver,
    get_naver_user_info,
    request_validation_to_kakao,
    request_validation_to_naver,
    request_oauth_access_token_to_google,
    get_google_user_info,
)
from app.http.requests.view.oauth.v1.oauth_request import (
    GetOAuthRequest,
    CreateUserRequest,
)
from app.http.responses.presenters.oauth_presenter import OAuthPresenter
from app.http.view import api
from core.domains.oauth.use_case.oauth_use_case import CreateTokenWithUserUseCase
from core.exception import InvalidRequestException
from core.use_case_output import UseCaseFailureOutput, FailureType


@api.route("/v1/oauth", methods=["GET"])
@swag_from("request_oauth.yml", methods=["GET"])
def request_oauth_to_third_party() -> Any:
    """
    Parameter : third_party("kakao" or "naver" or "google")
    Return : redirect -> redirect_url
    """
    provider_list = tuple([provider.value for provider in list(ProviderEnum)])
    parameter = request.args.get("provider")

    if not parameter:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.NOT_FOUND_ERROR,
                message=f"Parameter 'provider' is not found, Available parameters are {provider_list}",
            ),
            status_code=HTTPStatus.NOT_FOUND,
        )

    try:
        GetOAuthRequest(provider=parameter).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid provider input, Available parameters are {provider_list}",
            )
        )

    host_url = (
        OAuthBaseHostEnum.OAUTH_REDIRECT_HOST.value
        if request.environ.get("HTTP_X_REAL_IP", request.remote_addr) != "127.0.0.1"
        else request.host_url
    )

    if parameter == ProviderEnum.NAVER.value:
        redirect_to = host_url + OAuthNaverEnum.REDIRECT_PATH.value
        return oauth.naver.authorize_redirect(redirect_to)
    elif parameter == ProviderEnum.GOOGLE.value:
        redirect_to = host_url + OAuthGoogleEnum.REDIRECT_PATH.value
        return oauth.google.authorize_redirect(redirect_to)
    redirect_to = host_url + OAuthKakaoEnum.REDIRECT_PATH.value
    return oauth.kakao.authorize_redirect(redirect_to)


@api.route("/v1/oauth/kakao/web", methods=["GET"])
@swag_from("fetch_kakao_access_token.yml", methods=["GET"])
def fetch_kakao_access_token() -> Any:
    provider = ProviderEnum.KAKAO.value
    code = request.args.get("code")

    if not code:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get Authorization code from Kakao",
            )
        )

    # 인가 서버 -> Access_Token 요청
    token_result = request_oauth_access_token_to_kakao(code=code)

    if token_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get OAuth token info from Kakao",
            )
        )
    kakao_token_info = token_result.json()

    # 자원 서버 -> User_info 요청
    user_info_result = get_kakao_user_info(kakao_token_info)
    if user_info_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get user info from Kakao",
            )
        )
    user_info = user_info_result.json()

    # DTO 생성
    try:
        dto = CreateUserRequest(
            provider=provider, provider_id=str(user_info.get("id"))
        ).validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR, message=f"{e.message}"
            )
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))


@api.route("/v1/oauth/naver/web", methods=["GET"])
@swag_from("fetch_naver_access_token.yml", methods=["GET"])
def fetch_naver_access_token() -> Any:
    provider = ProviderEnum.NAVER.value
    code = request.args.get("code")

    if not code:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get Authorization code from Naver",
            )
        )

    # 인가 서버 -> Access_Token 요청
    token_result = request_oauth_access_token_to_naver(code=code)

    if token_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get OAuth token info from Naver",
            )
        )
    naver_token_info = token_result.json()

    # 자원 서버 요청
    user_info_result = get_naver_user_info(naver_token_info)
    if user_info_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get user info from naver",
            )
        )
    user_info = user_info_result.json()

    # DTO 생성
    try:
        dto = CreateUserRequest(
            provider=provider, provider_id=user_info.get("response")["id"]
        ).validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR, message=f"{e.message}"
            )
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))


@api.route("/v1/oauth/kakao", methods=["GET"])
@swag_from("login_kakao_view.yml", methods=["GET"])
def login_kakao_view() -> Any:
    """
        Live kakao login
        header : Bearer token
        return : Captain JWT access_token
    """
    auth_header = request.headers.get("Authorization")
    bearer, _, token = auth_header.partition(" ")

    validation_result = request_validation_to_kakao(access_token=token)

    if validation_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Validation Failed from Kakao",
            )
        )
    validation_data = validation_result.json()
    provider = ProviderEnum.KAKAO.value
    # DTO 생성
    try:
        dto = CreateUserRequest(
            provider=provider, provider_id=str(validation_data.get("id"))
        ).validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR, message=f"{e.message}"
            )
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))


@api.route("/v1/oauth/naver", methods=["GET"])
@swag_from("login_naver_view.yml", methods=["GET"])
def login_naver_view() -> Any:
    """
        Live naver login
        header : Bearer token
        return : Captain JWT access_token
    """
    auth_header = request.headers.get("Authorization")
    bearer, _, token = auth_header.partition(" ")

    validation_result = request_validation_to_naver(access_token=token)

    if validation_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Validation Failed from Naver",
            )
        )
    token_info = {"access_token": token}

    # 자원 서버 요청
    user_info_result = get_naver_user_info(token_info)
    if user_info_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get user info from naver",
            )
        )
    user_info = user_info_result.json()
    provider = ProviderEnum.NAVER.value

    # DTO 생성
    try:
        dto = CreateUserRequest(
            provider=provider, provider_id=str(user_info.get("id"))
        ).validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR, message=f"{e.message}"
            )
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))


@api.route("/v1/oauth/google/web", methods=["GET"])
@swag_from("fetch_google_access_token.yml", methods=["GET"])
def fetch_google_access_token() -> Any:
    """
        for test web in server
    """
    provider = ProviderEnum.GOOGLE.value
    code = request.args.get("code")

    if not code:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get Authorization code from Google",
            )
        )
    # 인가 서버 -> Access_Token 요청
    token_result = request_oauth_access_token_to_google(code=code)

    if token_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get OAuth token info from Google",
            )
        )
    google_token_info = token_result.json()

    # 자원 서버 요청
    user_info_result = get_google_user_info(google_token_info)
    if user_info_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get user info from Google",
            )
        )
    user_info = user_info_result.json()

    # DTO 생성
    try:
        dto = CreateUserRequest(
            provider=provider, provider_id=str(user_info.get("sub"))
        ).validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR, message=f"{e.message}"
            )
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))


@api.route("/v1/oauth/google", methods=["GET"])
@swag_from("login_google_view.yml", methods=["GET"])
def login_google_view() -> Any:
    """
        Live google login
        header : Bearer token
        return : Captain JWT access_token
    """
    auth_header = request.headers.get("Authorization")
    bearer, _, token = auth_header.partition(" ")

    token_info = {"access_token": token}

    # 자원 서버 요청
    user_info_result = get_google_user_info(token_info)
    if user_info_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message="Failed get user info from Google",
            )
        )
    user_info = user_info_result.json()
    provider = ProviderEnum.GOOGLE.value

    # DTO 생성
    try:
        dto = CreateUserRequest(
            provider=provider, provider_id=str(user_info.get("sub"))
        ).validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR, message=f"{e.message}"
            )
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))
