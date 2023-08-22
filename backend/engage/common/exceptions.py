from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler


class ProtectDeleteException(APIException):
    detail = None
    status_code = status.HTTP_409_CONFLICT

    def __init__(self, message):
        ProtectDeleteException.detail = message


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None and response.data and hasattr(exc, 'default_code'):
        response.data['code'] = exc.default_code

    return response
