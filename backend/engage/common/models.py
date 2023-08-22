import datetime

from django.db import models
from django.db.models import Max, F
from django.utils.translation import ugettext_lazy as _
from parler.models import TranslatableModel


class TenantModel(models.Model):
    tenant = models.UUIDField(_('Tenant'))

    class Meta:
        abstract = True


class TimeStampedModel(models.Model):  # 
    """
    An abstract base class model that provides self-
    updating ``created`` and ``modified`` fields.
    """
    created = models.DateTimeField(_('Created Date'), auto_now_add=True)
    modified = models.DateTimeField(_('Modified Date'), auto_now=True)

    class Meta:
        abstract = True

class TranslatableTimeStampedModel(TranslatableModel):  # models.Model
    """
    An abstract base class model that provides self-
    updating ``created`` and ``modified`` fields.
    """
    created = models.DateTimeField(_('Created Date'), auto_now_add=True)
    modified = models.DateTimeField(_('Modified Date'), auto_now=True)

    class Meta:
        abstract = True


class PublishableModel(models.Model):
    publication_date = models.DateField(blank=True, null=True)
    is_published = models.BooleanField(default=False)

    class Meta:
        abstract = True

    @property
    def is_visible(self):
        return self.is_published and (
            self.publication_date is None
            or self.publication_date <= datetime.date.today()
        )


class MetadataModel(models.Model):
    metadata = models.JSONField(blank=True, null=True, default=dict)
    private_metadata = models.JSONField(
        blank=True, null=True, default=dict
    )

    class Meta:
        abstract = True

    def get_value_from_private_metadata(self, key, default=None):
        return self.private_metadata.get(key, default)

    def store_value_in_private_metadata(self, items):
        if not self.private_metadata:
            self.private_metadata = {}
        self.private_metadata.update(items)

    def clear_private_metadata(self):
        self.private_metadata = {}

    def delete_value_from_private_metadata(self, key):
        if key in self.private_metadata:
            del self.private_metadata[key]

    def get_value_from_metadata(self, key, default=None):
        return self.metadata.get(key, default)

    def store_value_in_metadata(self, items):
        if not self.metadata:
            self.metadata = {}
        self.metadata.update(items)

    def clear_metadata(self):
        self.metadata = {}

    def delete_value_from_metadata(self, key):
        if key in self.metadata:
            del self.metadata[key]


class SortableModel(models.Model):
    sort_order = models.IntegerField(editable=False, db_index=True, null=True)

    class Meta:
        abstract = True

    def get_ordering_queryset(self):
        raise NotImplementedError("Unknown ordering queryset")

    def get_max_sort_order(self, qs):
        existing_max = qs.aggregate(Max("sort_order"))
        existing_max = existing_max.get("sort_order__max")
        return existing_max

    def save(self, *args, **kwargs):
        if self.pk is None:
            qs = self.get_ordering_queryset()
            existing_max = self.get_max_sort_order(qs)
            self.sort_order = 0 if existing_max is None else existing_max + 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.sort_order is not None:
            qs = self.get_ordering_queryset()
            qs.filter(sort_order__gt=self.sort_order).update(
                sort_order=F("sort_order") - 1
            )
        super().delete(*args, **kwargs)
