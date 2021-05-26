from typing import Union

from core.domains.authentication.dto.authentication_dto import UpdateJwtDto
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput


class UpdateJwtUseCase:
    def execute(self, dto: UpdateJwtDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        return UseCaseSuccessOutput()
