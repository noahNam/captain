from typing import Union

from pydantic import ValidationError

from app.http.responses import failure_response, success_response
from core.domains.oauth.schema.oauth_schema import ResponseOAuthSchema
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class OAuthPresenter:
    def transform(self, output: Union[UseCaseSuccessOutput, UseCaseFailureOutput]):
        if isinstance(output, UseCaseSuccessOutput):
            value = output.value
            try:
                schema = ResponseOAuthSchema(access_token=value.get("access_token"),
                                             refresh_token=value.get("refresh_token"),)
            except ValidationError as e:
                print(e)
                return failure_response(
                    UseCaseFailureOutput(
                        type=FailureType.SYSTEM_ERROR,
                        message="response schema validation error",
                    )
                )
            result = {
                "data": {"token_info": schema.dict()},
                "meta": {"cursor": output.meta},
            }
            return success_response(result=result)
        elif isinstance(output, UseCaseFailureOutput):
            return failure_response(output=output)
