from typing import Union
from app.http.responses import failure_response
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput


class OAuthPresenter:
    def transform(self, output: Union[UseCaseSuccessOutput, UseCaseFailureOutput]):
        """
        GetOAuthUseCase -> OAuth request to Third party -> result
        """
        return failure_response(output=output)
