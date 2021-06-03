from http import HTTPStatus

from flask import jsonify

from core.use_case_output import UseCaseFailureOutput


def success_response(result):
    return jsonify(**result), HTTPStatus.OK


def failure_response(
    output: UseCaseFailureOutput, status_code: int = HTTPStatus.BAD_REQUEST
):
    return jsonify(detail=output.detail, message=output.message), status_code
