from http import HTTPStatus

from flasgger import swag_from
from flask import request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions.utils.log_helper import logger_
from app.http.requests.view.authentication.authentication_request import (
    AllowedExpiredJwtTokenRequest,
    LogoutRequest, AllowedExpiredJwtTokenWithUUIDRequest,
)
from app.http.responses import failure_response
from app.http.responses.presenters.authentication_presenter import (
    UpdateJwtPresenter,
    LogoutPresenter,
    VerificationJwtPresenter,
)
from app.http.view import api
from app.http.view.authentication import auth_required
from core.domains.authentication.use_case.v1.authentication_use_case import (
    UpdateJwtUseCase,
    LogoutUseCase,
    VerificationJwtUseCase,
)
from core.exception import (
    InvalidRequestException,
    TokenNotFoundError,
    InvalidTokenError,
)
from core.use_case_output import UseCaseFailureOutput, FailureType

logger = logger_.getLogger(__name__)


def check_jwt_allow_expired(auth_header: str) -> bytes:
    prefix = "Bearer"

    # 헤더에 토큰 없을 경우
    if not auth_header:
        raise TokenNotFoundError

    bearer, _, token = auth_header.partition(" ")

    # 'Bearer' 로 시작하지 않을 경우
    if bearer != prefix:
        raise InvalidTokenError

    return token.encode("utf-8")


@api.route("/v1/refresh", methods=["GET"])
@swag_from("update_token_view.yml", methods=["GET"])
def token_update_view():
    """
        Update request from tanos
        - JWT 토큰만 업데이트
        - UUID는 받지 않음
    """
    auth_header = request.headers.get("Authorization")

    try:
        token_to_bytes = check_jwt_allow_expired(auth_header=auth_header)
    except TokenNotFoundError as e:
        logger.error(f"[token_update_view][check_jwt_allow_expired] Error : {e.msg}, ")
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.NOT_FOUND_ERROR,
                message=f"Authorization header is not provided",
            ),
            status_code=HTTPStatus.NOT_FOUND,
        )
    except InvalidTokenError as e:
        logger.error(f"[token_update_view][check_jwt_allow_expired] Error : {e.msg}, ")
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid Authorization header prefix",
            )
        )

    # 토큰 자체에 대한 유효성 검증
    try:
        dto = AllowedExpiredJwtTokenRequest(
            token=token_to_bytes
        ).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid token input from header",
            )
        )
    return UpdateJwtPresenter().transform(UpdateJwtUseCase().execute(dto=dto))


@api.route("/v1/logout", methods=["POST"])
@jwt_required
@auth_required
@swag_from("logout_view.yml", methods=["POST"])
def logout_view():
    """
        user logout from client
    """
    auth_header = request.headers.get("Authorization")
    bearer, _, token = auth_header.partition(" ")

    user_id = get_jwt_identity()

    try:
        dto = LogoutRequest(
            access_token=token, user_id=user_id
        ).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid token input from header",
            )
        )

    return LogoutPresenter().transform(LogoutUseCase().execute(dto=dto))


@api.route("/v1/verification", methods=["GET"])
@swag_from("verification_token_view.yml", methods=["GET"])
def verification_view():
    """
        Verification from Client
        - Access, Refresh 토큰 모두 만료된 토큰도 허용
        - UUID : UUID_v4
    """
    auth_header = request.headers.get("Authorization")
    uuid_v4 = request.args.get("uuid")

    try:
        token_to_bytes = check_jwt_allow_expired(auth_header=auth_header)
    except TokenNotFoundError as e:
        logger.error(f"[verification_view][check_jwt_allow_expired] Error : {e.msg}, ")
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.NOT_FOUND_ERROR,
                message=f"Authorization header is not provided",
            ),
            status_code=HTTPStatus.NOT_FOUND,
        )
    except InvalidTokenError as e:
        logger.error(f"[verification_view][check_jwt_allow_expired] Error : {e.msg}, ")
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid Authorization header prefix",
            )
        )

    # 토큰 자체에 대한 유효성 검증
    try:
        dto = AllowedExpiredJwtTokenWithUUIDRequest(
            token=token_to_bytes,
            uuid=uuid_v4
        ).validate_request_and_make_dto()
    except InvalidRequestException:
        return failure_response(
            UseCaseFailureOutput(
                detail=FailureType.INVALID_REQUEST_ERROR,
                message=f"Invalid token input from header",
            )
        )

    return VerificationJwtPresenter().transform(
        VerificationJwtUseCase().execute(dto=dto)
    )
