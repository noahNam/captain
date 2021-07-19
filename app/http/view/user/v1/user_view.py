from flasgger import swag_from
from flask_jwt_extended import jwt_required, current_user

from app.http.requests.view.user.v1.user_request import GetUserRequest, GetUserProviderRequest
from app.http.responses import failure_response
from app.http.responses.presenters.user_presenter import UserPresenter, GetUserProviderPresenter
from app.http.view import auth_required, api
from app.http.view.authentication import user_id
from core.domains.user.use_case.v1.user_use_case import GetUserUseCase, GetUserProviderUseCase
from core.use_case_output import FailureType, UseCaseFailureOutput


@api.route("/v1/users/<int:user_id>", methods=["GET"])
@jwt_required
@auth_required
def get_user_view(user_id):
    dto = GetUserRequest(user_id=user_id).validate_request_and_make_dto()
    if not dto:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR)
        )

    return UserPresenter().transform(GetUserUseCase().execute(dto=dto))


@api.route("/v1/users/provider", methods=["GET"])
@jwt_required
@auth_required
def get_user_provider_view():
    dto = GetUserProviderRequest(user_id=user_id).validate_request_and_make_dto()
    if not dto:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR)
        )

    return GetUserProviderPresenter().transform(GetUserProviderUseCase().execute(dto=dto))
