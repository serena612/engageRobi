from django.db import models


class LabelChoices(models.TextChoices):
    @classmethod
    def options(cls, values=None):
        if values:
            return [{'label': label,
                     'value': value} for value, label in cls.choices if
                    value in values]
        else:
            return [{'label': label,
                     'value': value} for value, label in cls.choices]