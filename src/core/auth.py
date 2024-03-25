import base64
import binascii

from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from users.selectors import user_get


class BasicAuthentication(authentication.BaseAuthentication):
    """
    HTTP Basic Authentication class.
    """
    def authenticate(self, request: Request):
        auth_prefix = 'Basic '
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None
        if not auth_header.startswith(auth_prefix):
            return None

        try:
            encoded_credentials = auth_header.removeprefix(auth_prefix)
            credentials = base64.b64decode(encoded_credentials)
        except binascii.Error:
            return None

        username, password = credentials.decode().split(':')
        user = user_get(username=username)
        if user is None or not user.check_password(password):
            error = 'Invalid username/password pair.'
            raise AuthenticationFailed(error)
        return (user, None)
