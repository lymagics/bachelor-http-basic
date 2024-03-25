from rest_framework.decorators import api_view, authentication_classes, \
    permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from core.auth import BasicAuthentication
from users import services
from users.api.schemas import UserIn, UserOut


@api_view(['POST'])
def user_create(request):
    schema = UserIn(data=request.data)
    schema.is_valid(raise_exception=True)
    services.user_create(**schema.validated_data)
    return Response(status=201)


@api_view(['GET'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def user_get(request):
    data = UserOut(request.user).data
    return Response(data)
