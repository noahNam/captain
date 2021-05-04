import os
import requests
from flask import request, url_for
from app import oauth
from app.extensions import KAKAO_API_BASE_URL, KAKAO_GET_ACCESS_TOKEN_END_POINT
from app.extensions.utils.oauth_helper import request_default_header, KAKAO_REDIRECT_URL
from app.http.requests.view.oauth.v1.oauth_request import GetOAuthRequest
from app.http.responses import failure_response
from app.http.view import api
from core.use_case_output import UseCaseFailureOutput, FailureType


@api.route("/v1/oauth", methods=["GET"])
def request_oauth_to_third_party():
    """
    Parameter : third_party("kakao" or "naver")
    Return : redirect -> fetch_{third_party}_access_token view
    """
    parameter = request.args.get("provider")
    dto = GetOAuthRequest(provider=parameter).validate_request_and_make_dto()
    if not dto:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR)
        )
    redirect_url = "http://127.0.0.1:5000" + url_for("api.fetch_kakao_access_token")

    return oauth.kakao.authorize_redirect(redirect_url)


@api.route("/v1/oauth/kakao", methods=["GET"])
def fetch_kakao_access_token():
    code = request.args.get("code", None)

    if code is None:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR)
        )

    return requests.post(
        url=KAKAO_API_BASE_URL + KAKAO_GET_ACCESS_TOKEN_END_POINT,
        headers=request_default_header,
        data={
            "grant_type": "authorization_code",
            "client_id": os.getenv("KAKAO_CLIENT_ID"),
            "client_secret": os.getenv("KAKAO_CLIENT_SECRET"),
            "redirect_uri": KAKAO_REDIRECT_URL,
            "code": code,
        },
    ).json()
    # return OAuthPresenter().transform(GetOAuthUseCase().execute())


@api.route("/v1/oauth/naver", methods=["GET"])
def fetch_naver_access_token():
    pass
