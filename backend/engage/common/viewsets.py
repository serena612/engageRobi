import json

from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from django.db.models import ProtectedError
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_nested import viewsets as rfn_viewsets

from .exceptions import ProtectDeleteException


def get_related_objects(instance):
    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([instance])
    return collector


class NestedViewSetMixin(rfn_viewsets.NestedViewSetMixin):

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return generics.GenericAPIView.get_queryset(self)

        return super().get_queryset()


class DeleteCheckViewSetMixin:

    @action(['GET'], detail=True)
    def check_relations(self, request, *args, **kwargs):
        instance = self.get_object()
        collector = get_related_objects(instance)
        return Response({
            'edges': list(collector.edges),
            'protected': list(collector.protected)
        })

    def perform_destroy(self, instance):
        try:
            instance.delete()
        except ProtectedError as e:
            collector = get_related_objects(instance)
            raise ProtectDeleteException(
                json.dumps({'protected': list(collector.protected)}))


class SoftDeleteViewSetMixin:

    @action(['POST'], detail=True)
    def recover(self, request, *args, **kwargs):
        instance = self.get_object()
        if not hasattr(instance, 'deleted_at') and instance.deleted_at is None:
            return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

        instance.deleted_at = None
        instance.save()

        return Response(status=status.HTTP_200_OK)

    @action(['POST'], detail=True)
    def deactivate(self, request, *args, **kwargs):
        instance = self.get_object()
        if not hasattr(instance,
                       'deleted_at') and instance.deleted_at is not None:
            return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

        instance.deleted_at = timezone.now()
        instance.save()

        return Response(status=status.HTTP_200_OK)
