from app import oauth


class GetOAuthUseCase:
    """
    todo: Authlib -> Use Flask OAuth Client -> request OAuth to Third party
          -> fetch_access_token -> request user_info -> validate user table -> JWT
    """

    def execute(self, dto):
        return dto
