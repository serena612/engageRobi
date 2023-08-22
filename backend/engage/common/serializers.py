import uuid

from rest_framework import serializers


class CurrentTenantDefault:
    requires_context = True

    def __call__(self, serializer_field):
        # TEMPORARY UNTIL SSO IS FINALIZED
        # return serializer_field.context['request'].tenant
        return uuid.uuid4()

    def __repr__(self):
        return '%s()' % self.__class__.__name__


class TenantTranslatableModelSerializer(serializers.Serializer):
    tenant = serializers.HiddenField(
        default=CurrentTenantDefault()
    )
