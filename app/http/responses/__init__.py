from http import HTTPStatus

from flask import jsonify

from core.use_case_output import UseCaseFailureOutput


def success_response(result):
    return jsonify(**result), HTTPStatus.OK


def failure_response(
    output: UseCaseFailureOutput, status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
):
    return jsonify(type=output.type, error_message=output.message), status_code
