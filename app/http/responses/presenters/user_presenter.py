from typing import Union

from pydantic import ValidationError

from app.http.responses import failure_response, success_response
from core.domains.user.schema.user_schema import UserResponseSchema
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class UserPresenter:
    def transform(self, output: Union[UseCaseSuccessOutput, UseCaseFailureOutput]):
        if isinstance(output, UseCaseSuccessOutput):
            value = output.value
            try:
                schema = UserResponseSchema(id=value.id,
                                            provider=value.provider,
                                            provider_id=value.provider_id)
            except ValidationError as e:
                print(e)
                return failure_response(
                    UseCaseFailureOutput(
                        type=FailureType.SYSTEM_ERROR,
                        message="response schema validation error",
                    )
                )
            result = {
                "data": {"user": schema.dict()},
                "meta": {"cursor": output.meta},
            }
            return success_response(result=result)
        elif isinstance(output, UseCaseFailureOutput):
            return failure_response(output=output)
