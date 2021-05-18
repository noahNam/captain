from typing import Any

from flasgger import swag_from
from flask import request

from app import oauth
from app.http.responses import failure_response
from core.domains.oauth.enum.oauth_enum import OAuthKakaoEnum, ProviderEnum
from app.extensions.utils.oauth_helper import request_oauth_access_token_to_kakao, get_kakao_user_info
from app.http.requests.view.oauth.v1.oauth_request import GetOAuthRequest, CreateUserRequest
from app.http.responses.presenters.oauth_presenter import OAuthPresenter
from app.http.view import api
from core.domains.oauth.use_case.oauth_use_case import CreateTokenWithUserUseCase
from core.exception import InvalidRequestException
from core.use_case_output import UseCaseFailureOutput, FailureType


@api.route("/v1/oauth", methods=["GET"])
@swag_from("request_oauth.yml", methods=["GET"])
def request_oauth_to_third_party() -> Any:
    """
    Parameter : third_party("kakao" or "naver")
    Return : redirect -> redirect_url
    """
    provider_list = tuple([provider.value for provider in list(ProviderEnum)])
    parameter = request.args.get("provider")

    if not parameter:
        return failure_response(
            UseCaseFailureOutput(
                type=FailureType.INVALID_REQUEST_ERROR,
                message=f"Parameter 'provider' is not found, Available parameters are {provider_list}")
        )

    try:
        GetOAuthRequest(provider=parameter).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                type=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid provider input, Available parameters are {provider_list}")
        )

    # need to be fix (only redirect to kakao api hard coding)
    redirect_to = OAuthKakaoEnum.REDIRECT_URL.value
    # if parameter == ProviderEnum.NAVER.value:
    #     redirect_to = OAuthNaverEnum.REDIRECT_URL.value
    return oauth.kakao.authorize_redirect(redirect_to)


@api.route("/v1/oauth/kakao", methods=["GET"])
@swag_from("get_kakao_id_and_create_jwt.yml", methods=["GET"])
def fetch_kakao_access_token() -> Any:
    provider = ProviderEnum.KAKAO.value
    kakao_token_info = None
    user_info = None
    code = request.args.get("code")

    if not code:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR,
                                 message="Failed get Authorization code from Kakao")
        )

    # 인가 서버 -> Access_Token 요청
    token_result = request_oauth_access_token_to_kakao(code=code)

    if token_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR,
                                 message="Failed get OAuth token info from Kakao")
        )
    kakao_token_info = token_result.json()

    # 자원 서버 -> User_info 요청
    user_info_result = get_kakao_user_info(kakao_token_info)
    if user_info_result.raise_for_status():
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR,
                                 message="Failed get user info from Kakao")
        )
    user_info = user_info_result.json()

    # DTO 생성
    try:
        dto = CreateUserRequest(provider=provider, provider_id=user_info.get("id")) \
            .validate_request_and_make_dto()
    except InvalidRequestException as e:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR,
                                 message=f"{e.message}")
        )
    return OAuthPresenter().transform(CreateTokenWithUserUseCase().execute(dto=dto))


@api.route("/v1/oauth/naver", methods=["GET"])
def fetch_naver_access_token():
    pass
