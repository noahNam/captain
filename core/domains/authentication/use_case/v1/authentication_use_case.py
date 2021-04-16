from typing import Union

from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput


class AuthenticationUseCase:
    def execute(self) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        return UseCaseSuccessOutput()
