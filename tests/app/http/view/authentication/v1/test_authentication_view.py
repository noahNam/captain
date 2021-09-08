from http import HTTPStatus
from typing import List

from flask import url_for
from flask.ctx import RequestContext
from flask.testing import FlaskClient
from flask_jwt_extended import create_access_token, create_refresh_token
from sqlalchemy.orm import scoped_session

from app.extensions import RedisClient
from app.persistence.model import BlacklistModel, JwtModel
from core.domains.authentication.dto.authentication_dto import JwtWithUUIDDto
from core.domains.authentication.repository.authentication_repository import (
    AuthenticationRepository,
)
from core.domains.user.repository.user_repository import UserRepository
from core.use_case_output import FailureType
from tests.app.http.requests.view.authentication.v1.test_authentication_request import (
    create_invalid_refresh_token,
)
from tests.seeder.factory import UserBaseFactory, UserFactory


def test_update_view_when_request_without_jwt_then_raise_validation_error(
    client: FlaskClient, test_request_context: RequestContext
):
    """
        given : Nothing
        when : [GET] /api/captain/v1/refresh
        then : raise InvalidRequestException
    """
    with test_request_context:
        response = client.get(url_for("api.token_update_view"))

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response.get_json()["detail"] == FailureType.NOT_FOUND_ERROR


def test_update_view_when_request_with_token_with_wrong_prefix_then_raise_validation_error(
    client: FlaskClient,
    test_request_context: RequestContext,
    make_header,
    create_base_users: List[UserBaseFactory],
):
    """
        given : JWT (Header with wrong prefix)
        when : [GET] /api/captain/v1/refresh
        then : raise InvalidRequestException
    """
    authorization = "Wrong " + create_access_token(identity=create_base_users[0].id)
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.get(url_for("api.token_update_view"), headers=headers)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json()["detail"] == FailureType.INVALID_REQUEST_ERROR


def test_update_view_when_request_with_token_with_wrong_token_then_raise_validation_error(
    client: FlaskClient,
    test_request_context: RequestContext,
    make_header,
    create_base_users: List[UserBaseFactory],
):
    """
        given : wrong JWT
        when : [GET] /api/captain/v1/refresh
        then : raise InvalidRequestException
    """
    authorization = "Bearer " + "something wrong token"
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.get(url_for("api.token_update_view"), headers=headers)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json()["detail"] == FailureType.INVALID_REQUEST_ERROR


def test_update_view(
    client: FlaskClient,
    test_request_context: RequestContext,
    make_header,
    make_expired_authorization,
    create_base_users: List[UserBaseFactory],
    session: scoped_session,
):
    """
        given : wrong JWT
        when : [GET] /api/captain/v1/refresh
        then : return updated access_token
    """
    user_id = create_base_users[0].id

    authorization = make_expired_authorization(user_id=user_id)
    headers = make_header(authorization=authorization)

    expired_token = authorization[7:]
    valid_refresh_token = create_refresh_token(identity=user_id)
    jwt_model = JwtModel(
        user_id=user_id, access_token=expired_token, refresh_token=valid_refresh_token,
    )
    session.add(jwt_model)
    session.commit()

    with test_request_context:
        response = client.get(url_for("api.token_update_view"), headers=headers)
    data = response.get_json().get("data")

    assert response.status_code == 200
    assert isinstance(data["token_info"]["access_token"], str)


def test_logout_view_when_request_with_not_jwt_then_response_405(
    client: FlaskClient, test_request_context: RequestContext
):
    """
        given : Nothing
        when : [GET] /api/captain/v1/logout
        then : response 405 Method not allowed
    """
    with test_request_context:
        response = client.get(url_for("api.logout_view"))

    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED


def test_logout_view_when_request_with_token_with_wrong_token_then_response_405(
    client: FlaskClient,
    test_request_context: RequestContext,
    make_header,
    create_base_users: List[UserBaseFactory],
):
    """
        given : wrong JWT
        when : [GET] /api/captain/v1/logout
        then : response 405 Method not allowed
    """
    authorization = "Bearer " + "something wrong token"
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.get(url_for("api.logout_view"), headers=headers)

    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED


def test_logout_view_when_request_with_expired_jwt_then_response_401(
    client: FlaskClient,
    test_request_context: RequestContext,
    make_header,
    make_expired_authorization,
    create_base_users: List[UserBaseFactory],
):
    """
        given : Nothing
        when : [GET] /api/captain/v1/logout
        then : response 401 Unauthorized
    """
    user_id = create_base_users[0].id

    authorization = make_expired_authorization(user_id=user_id)
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.post(url_for("api.logout_view"), headers=headers)

    assert response.status_code == HTTPStatus.UNAUTHORIZED


def test_logout_view(
    client: FlaskClient,
    test_request_context: RequestContext,
    redis: RedisClient,
    session: scoped_session,
    make_header,
    make_authorization,
    create_base_users: List[UserBaseFactory],
):
    """
        given : login with valid access_token
        when : [GET] /api/captain/v1/logout
        then : blacklist created in DB, redis
    """
    user_id = create_base_users[0].id

    authorization = make_authorization(user_id=user_id)
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.post(url_for("api.logout_view"), headers=headers)

    data = response.get_json().get("data")

    # redis check
    blacklists_in_redis = redis.smembers("jwt_blacklist")

    # db check
    blacklist = session.query(BlacklistModel).filter_by(user_id=user_id).first()

    assert response.status_code == 200
    assert isinstance(data["logout"]["blacklist_token"], str)
    assert isinstance(data["logout"]["expired_at"], str)
    assert blacklists_in_redis is not None
    assert blacklist.access_token.encode("utf-8") in blacklists_in_redis


def test_verification_view_when_get_expired_token_with_valid_refresh_token(
    client: FlaskClient,
    test_request_context: RequestContext,
    redis: RedisClient,
    make_header,
    make_expired_authorization,
    create_base_users: List[UserBaseFactory],
    session: scoped_session,
):
    """
        given: expired access_token from header, valid refresh_token
        when: [GET] /api/captain/v1/verification
        then: return updated access_token
    """
    user_id = create_base_users[0].id
    uuid = create_base_users[0].uuid

    authorization = make_expired_authorization(user_id=user_id)
    headers = make_header(authorization=authorization)

    expired_token = authorization[7:]
    valid_refresh_token = create_refresh_token(identity=user_id)
    jwt_model = JwtModel(
        user_id=user_id, access_token=expired_token, refresh_token=valid_refresh_token,
    )
    session.add(jwt_model)
    session.commit()

    token_info = jwt_model.to_entity()

    # to redis
    AuthenticationRepository().set_token_to_cache(token_info=token_info)
    UserRepository().set_user_uuid_to_cache(user_id=user_id, uuid=uuid)

    with test_request_context:
        response = client.get(
            url_for("api.verification_view", uuid=uuid), headers=headers
        )

    data = response.get_json().get("data")

    assert response.status_code == 200
    assert isinstance(data["token_info"]["access_token"], str)
    assert expired_token != data["token_info"]["access_token"]


def test_verification_view_when_get_expired_token_with_invalid_refresh_token(
    client: FlaskClient,
    test_request_context: RequestContext,
    redis: RedisClient,
    make_header,
    make_expired_authorization,
    create_base_users: List[UserBaseFactory],
    session: scoped_session,
):
    """
        given: expired access_token from header, invalid refresh_token or None
        when: [GET] /api/captain/v1/verification
        then: response 400
    """
    user_id = create_base_users[0].id
    uuid = create_base_users[0].uuid

    authorization = make_expired_authorization(user_id=user_id)
    headers = make_header(authorization=authorization)

    expired_token = authorization[7:]
    expired_refresh_token = create_invalid_refresh_token(user_id=user_id)
    jwt_model = JwtModel(
        user_id=user_id,
        access_token=expired_token,
        refresh_token=expired_refresh_token,
    )
    session.add(jwt_model)
    session.commit()

    token_info = jwt_model.to_entity()

    # to redis
    AuthenticationRepository().set_token_to_cache(token_info=token_info)
    UserRepository().set_user_uuid_to_cache(user_id=user_id, uuid=uuid)

    with test_request_context:
        response = client.get(
            url_for("api.verification_view", uuid=uuid), headers=headers
        )

    assert response.status_code == 400
