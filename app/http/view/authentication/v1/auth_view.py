from flask_jwt_extended import jwt_required

from app.http.responses.presenters.authentication_presenter import (
    AuthenticationPresenter,
)
from app.http.view import api
from app.http.view.authentication import auth_required
from core.domains.authentication.use_case.v1.authentication_use_case import (
    AuthenticationUseCase,
)


@api.route("/authentication/v1/", methods=["GET"])
@jwt_required
@auth_required
def auth_for_testing_view():
    """
    인증 테스트 뷰
    """
    return AuthenticationPresenter().transform(AuthenticationUseCase().execute())
