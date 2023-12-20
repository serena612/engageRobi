from django.conf import settings
from rest_framework import mixins, viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Region, OperatorAd
from . import serializers
from ..account.constants import CoinTransaction, Transaction
from ..account.models import UserTransactionHistory
from ..tournament.models import get_prize


class RegionViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                    viewsets.GenericViewSet):
    queryset = Region.objects.all()
    serializer_class = serializers.RegionSerializer
    lookup_field = 'code'

    @action(['POST'], detail=True)
    def switch(self, request, code):
        instance = self.get_object()
        response = Response()
        response.set_cookie(settings.REGION_COOKIE_NAME, instance.code)
        return response


class OperatorAdViewSet(viewsets.GenericViewSet):
    queryset = OperatorAd.objects.all()
    serializer_class = serializers.OperatorSerializer

    @action(['GET'], detail=True)
    def watch_ad(self, request):
        instance = self.get_object()
        return Response()


class OrderViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'redeem_package':
            return serializers.RedeemPackageSerializer
        else:
            return serializers.PurchaseCoinsSerializer

    @action(['POST'], detail=False)
    def redeem_package(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        redeem_package = serializer.validated_data['package']
        phone_number = request.user.mobile
        if redeem_package.prize_type == 'cash':
            prize = redeem_package.cash_amount
        else:
            prize = redeem_package.cash_amount
            # prize = redeem_package.actual_package
        if not get_prize(phone_number, prize, redeem_package.prize_type, request.user.subscription,0):
            return Response({'error': 'Error claiming prize'}, status=532)
        UserTransactionHistory.objects.create(
            user=request.user,
            amount=-redeem_package.coins,
            action=CoinTransaction.REDEEM,
            info = Transaction.REDEEM
        )

        return Response({'amount': redeem_package.coins,
                         'package_name': redeem_package.title})
    


    @action(['POST'], detail=False)
    def pay_fee(self, request):
        UserTransactionHistory.objects.create(
            user=request.user,
            amount=-30,
            action=CoinTransaction.PAY,
            info = Transaction.PAY
        )

        return Response({'amount': 30})

    @action(['POST'], detail=False)
    def buy_coins(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        coins_plan = serializer.validated_data['coins_plan']

        UserTransactionHistory.objects.create(
            user=request.user,
            amount=coins_plan.total,
            action=CoinTransaction.BUY,
            info= Transaction.BUY
        )

        return Response({'amount': coins_plan.total})
