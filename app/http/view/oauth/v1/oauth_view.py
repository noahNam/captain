from typing import Any
from flask import request
from app import oauth
from app.extensions.utils.enum.oauth_enum import OAuthKakaoEnum
from app.extensions.utils.oauth_helper import request_oauth_access_token_to_kakao, get_kakao_user_info
from app.http.requests.view.oauth.v1.oauth_request import GetOAuthRequest, CreateUserRequest
from app.http.responses.presenters.oauth_presenter import OAuthPresenter
from app.http.view import api
from core.domains.oauth.use_case.oauth_use_case import GetOAuthUseCase
from core.exception import InvalidRequestException


@api.route("/v1/oauth", methods=["GET"])
def request_oauth_to_third_party() -> Any:
    """
    Parameter : third_party("kakao" or "naver")
    Return : redirect -> redirect_url
    """
    parameter = request.args.get("provider")
    if not parameter:
        raise InvalidRequestException(
            message="Parameter 'provider' is not found, Available parameters are [ 'kakao', 'naver' ]")

    GetOAuthRequest(provider=parameter).validate_request_and_make_dto()

    # need to be fix (only redirect to kakao api hard coding)
    redirect_to = OAuthKakaoEnum.REDIRECT_URL.value
    # if parameter == "naver":
    #     redirect_to = OAuthNaverEnum.REDIRECT_URL.value

    return oauth.kakao.authorize_redirect(redirect_to)


@api.route("/v1/oauth/kakao", methods=["GET"])
def fetch_kakao_access_token() -> Any:
    provider = "kakao"
    kakao_token_info = None
    user_info = None
    code = request.args.get("code")

    if not code:
        raise InvalidRequestException(
            message="Authorization_code not passed")

    # 인가 서버 -> Access_Token 요청
    token_result = request_oauth_access_token_to_kakao(code=code)
    if not token_result.raise_for_status():
        kakao_token_info = token_result

    # 자원 서버 -> User_info 요청
    user_info_result = get_kakao_user_info(kakao_token_info)
    if not user_info_result.raise_for_status():
        user_info = user_info_result.json()

    # DTO 생성
    dto = CreateUserRequest(provider=provider, provider_id=user_info.get("id")).validate_request_and_make_dto()
    return OAuthPresenter().transform(GetOAuthUseCase().execute(dto=dto))


@api.route("/v1/oauth/naver", methods=["GET"])
def fetch_naver_access_token():
    pass
