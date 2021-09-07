from uuid import uuid4

import pytest

from app.http.requests.view.oauth.v1.oauth_request import (
    GetOAuthRequest,
    CreateUserRequest,
)
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.exception import InvalidRequestException

uuid_v4 = str(uuid4())


def test_when_valid_request_with_naver_then_success():
    result = GetOAuthRequest(
        provider=ProviderEnum.NAVER.value,
    ).validate_request_and_make_dto()
    assert result.provider == ProviderEnum.NAVER.value


def test_when_valid_request_with_kakao_then_success():
    result = GetOAuthRequest(
        provider=ProviderEnum.KAKAO.value,
    ).validate_request_and_make_dto()
    assert result.provider == ProviderEnum.KAKAO.value


def test_when_invalid_request_then_raise_validation_error():
    with pytest.raises(InvalidRequestException):
        GetOAuthRequest(provider="hawaii").validate_request_and_make_dto()


def test_when_valid_input_user_info_then_success():
    result = CreateUserRequest(
        provider=ProviderEnum.KAKAO.value,
        provider_id="12345",
        uuid=uuid_v4
    ).validate_request_and_make_dto()

    assert result.provider == ProviderEnum.KAKAO.value
    assert result.provider_id == "12345"
    assert result.uuid == uuid_v4


def test_when_invalid_input_user_info_then_fail():
    with pytest.raises(InvalidRequestException):
        CreateUserRequest(
            provider="not_provider", provider_id="None", uuid=uuid_v4
        ).validate_request_and_make_dto()
