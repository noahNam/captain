from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_current_user

from app.http.requests.view.authentication.authentication_request import UpdateTokenRequest, LogoutRequest
from app.http.responses import failure_response
from app.http.responses.presenters.authentication_presenter import UpdateJwtPresenter, LogoutPresenter
from app.http.view import api
from app.http.view.authentication import auth_required
from core.domains.authentication.use_case.v1.authentication_use_case import (
    UpdateJwtUseCase, LogoutUseCase,
)
from core.exception import InvalidRequestException
from core.use_case_output import UseCaseFailureOutput, FailureType


@api.route("/v1/refresh", methods=["GET"])
def token_update_view():
    """
        Update request from tanos
    """
    prefix = "Bearer"
    auth_header = request.headers.get("Authorization")

    # 헤더에 토큰 없을 경우
    if not auth_header:
        return failure_response(
            UseCaseFailureOutput(
                type=FailureType.INVALID_REQUEST_ERROR,
                message=f"Authorization header is not provided")
        )

    bearer, _, token = auth_header.partition(" ")

    # 'Bearer' 로 시작하지 않을 경우
    if bearer != prefix:
        return failure_response(
            UseCaseFailureOutput(
                type=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid Authorization header prefix")
        )

    token_to_bytes = token.encode("UTF-8")

    # 토큰 자체에 대한 유효성 검증
    try:
        dto = UpdateTokenRequest(token=token_to_bytes).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                type=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid token input from header")
        )

    return UpdateJwtPresenter().transform(UpdateJwtUseCase().execute(dto=dto))


@api.route("/v1/logout", methods=["POST"])
@jwt_required
@auth_required
def logout_view():
    """
        user logout from client
    """
    auth_header = request.headers.get("Authorization")
    bearer, _, token = auth_header.partition(" ")

    user_id = get_jwt_identity()

    token_to_bytes = token.encode("utf-8")

    try:
        dto = LogoutRequest(access_token=token_to_bytes, user_id=user_id).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                type=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid token input from header")
        )

    return LogoutPresenter().transform(LogoutUseCase().execute(dto=dto))
