from typing import Union

from pydantic import ValidationError

from app.extensions.utils.log_helper import logger_
from app.http.responses import failure_response, success_response
from core.domains.authentication.schema.authentication_schema import UpdateJwtResponseSchema
from core.use_case_output import UseCaseSuccessOutput, FailureType, UseCaseFailureOutput

logger = logger_.getLogger(__name__)


class UpdateJwtPresenter:
    def transform(self, output: Union[UseCaseSuccessOutput, UseCaseFailureOutput]):
        if isinstance(output, UseCaseSuccessOutput):
            value = output.value
            value_to_json = value.get_json()
            try:
                schema = UpdateJwtResponseSchema(access_token=value_to_json.get("access_token"))
            except ValidationError as e:
                logger.error(
                    f"[UpdateJwtPresenter][transform] value : {value} error : {e}")
                return failure_response(
                    UseCaseFailureOutput(
                        type=FailureType.SYSTEM_ERROR,
                        message="response schema validation error",
                    )
                )
            result = {
                "data": {"token_info": schema.dict()},
            }
            return success_response(result=result)
        elif isinstance(output, UseCaseFailureOutput):
            return failure_response(output=output)
