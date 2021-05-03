from app.http.requests.view.oauth.v1.oauth_request import GetOAuthRequest
from app.http.responses import failure_response
from app.http.responses.presenters.oauth_presenter import OAuthPresenter
from app.http.view import api
from core.domains.oauth.use_case.oauth_use_case import GetOAuthUseCase
from core.use_case_output import UseCaseFailureOutput, FailureType


@api.route("/v1/oauth", methods=["GET"])
def request_oauth_to_third_party(provider: str):
    """
    Parameter : third_party("kakao" or "naver")
    Todo : 요청 받은 파라미터 검증
            유효한 값이면, 해당 third_party oauth 인증 서버에 인증 요청 진행
            (Authlib 라이브러리 사용 예정 - flask oauth client)

    Return : to Presenter -> result
    """
    dto = GetOAuthRequest(provider=provider).validate_request_and_make_dto()
    if not dto:
        return failure_response(
            UseCaseFailureOutput(type=FailureType.INVALID_REQUEST_ERROR)
        )

    return OAuthPresenter().transform(GetOAuthUseCase().execute(dto=dto))
