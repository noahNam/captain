from typing import Dict, Any

import jwt

from app.extensions.utils.log_helper import logger_
from core.domains.oauth.enum.oauth_enum import OAuthAppleEnum
from core.exception import InvalidRequestException

logger = logger_.getLogger(__name__)


class AppleOAuthKey:
    """
        Apple Auth keys
        from [GET] https://appleid.apple.com/auth/keys
        more information: https://developer.apple.com/documentation/sign_in_with_apple/jwkset/keys
    """

    def __init__(self, kty: str, kid: str, use: str, alg: str, n: str, e: str):
        self.kty = kty
        self.kid = kid
        self.use = use
        self.alg = alg
        self.n = n
        self.e = e

    def get_decoded_token(self, token: str) -> Dict[str, Any]:
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"
        public_key = self.n + self.e
        signing_key = header + "\n" + public_key + "\n" + footer
        try:
            decoded_token = jwt.decode(
                jwt=token, key=signing_key, algorithms=[self.alg]
            )
            return decoded_token
        except Exception as e:
            logger.error(f"[AppleOAuthKey][get_decoded_token] error : {e}")
            raise InvalidRequestException(message=e)

    def is_valid_token(self, decoded_token: Dict[str, Any]) -> bool:
        # todo: "aud" 검증 추가(ex: com.toadhome.xx...)
        if decoded_token.get("iss") != OAuthAppleEnum.APPLE_ISS:
            return False
        return True
