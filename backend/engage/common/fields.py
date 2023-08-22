import base64
import binascii
import inspect
import importlib
import uuid
import six
import imghdr

from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers
from rest_framework.serializers import BaseSerializer
from rest_framework.fields import FileField, ImageField


def _signature_parameters(func):
    return inspect.signature(func).parameters.keys()


class Base64FieldMixin(object):
    ALLOWED_TYPES = NotImplemented
    INVALID_FILE_MESSAGE = NotImplemented
    INVALID_TYPE_MESSAGE = NotImplemented
    EMPTY_VALUES = (None, '', [], (), {})

    def __init__(self, *args, **kwargs):
        self.represent_in_base64 = kwargs.pop('represent_in_base64', False)
        super(Base64FieldMixin, self).__init__(*args, **kwargs)

    def to_internal_value(self, base64_data):
        # Check if this is a base64 string
        if base64_data in self.EMPTY_VALUES:
            return None

        if isinstance(base64_data, six.string_types):
            # Strip base64 header.
            if ';base64,' in base64_data:
                header, base64_data = base64_data.split(';base64,')
            # Try to decode the file. Return validation error if it fails.
            try:
                decoded_file = base64.b64decode(base64_data)
            except (TypeError, binascii.Error, ValueError):
                raise ValidationError(self.INVALID_FILE_MESSAGE)
            # Generate file name:
            # 12 characters are more than enough.
            file_name = str(uuid.uuid4())[:12]
            # Get the file name extension:
            file_extension = self.get_file_extension(file_name, decoded_file)
            if self.ALLOWED_TYPES and (file_extension not in self.ALLOWED_TYPES):
                raise ValidationError(self.INVALID_TYPE_MESSAGE)
            complete_file_name = file_name + "." + file_extension
            data = ContentFile(decoded_file, name=complete_file_name)
            return super(Base64FieldMixin, self).to_internal_value(data)
        raise ValidationError(_('This is not an base64 string'))

    def get_file_extension(self, filename, decoded_file):
        raise NotImplemented

    def to_representation(self, file):
        if self.represent_in_base64:
            try:
                with open(file.path, 'rb') as f:
                    return base64.b64encode(f.read()).decode()
            except Exception as e:
                print('Fails to decode file: %s (%s)' % (e.message, type(e)))
        else:
            return super(Base64FieldMixin, self).to_representation(file)


class Base64FileField(Base64FieldMixin, FileField):
    """
    A django-rest-framework field for handling file-uploads through raw post data.
    It uses base64 for en-/decoding the contents of the file.
    """
    ALLOWED_TYPES = []
    INVALID_FILE_MESSAGE = _("Please upload a valid file.")
    INVALID_TYPE_MESSAGE = _("The type of the file couldn't be determined.")

    def get_file_extension(self, filename, decoded_file):
        return imghdr.what(filename, decoded_file)


class Base64ImageField(Base64FieldMixin, ImageField):
    """
    A django-rest-framework field for handling image-uploads through raw post data.
    It uses base64 for en-/decoding the contents of the file.
    """
    ALLOWED_TYPES = (
        "jpeg",
        "jpg",
        "png",
        "gif"
    )
    INVALID_FILE_MESSAGE = _("Please upload a valid image.")
    INVALID_TYPE_MESSAGE = _("The type of the image couldn't be determined.")

    def get_file_extension(self, filename, decoded_file):
        extension = imghdr.what(filename, decoded_file)
        extension = "jpg" if extension == "jpeg" else extension
        return extension


class HybridImageField(Base64ImageField):
    """
    A django-rest-framework field for handling image-uploads through
    raw post data, with a fallback to multipart form data.
    """

    def to_internal_value(self, data):
        """
        Try Base64Field first, and then try the ImageField
        ``to_internal_value``, MRO doesn't work here because
        Base64FieldMixin throws before ImageField can run.
        """
        try:
            return Base64FieldMixin.to_internal_value(self, data)
        except ValidationError:
            return ImageField.to_internal_value(self, data)


class RecursiveField(serializers.Field):
    # This list of attributes determined by the attributes that
    # `rest_framework.serializers` calls to on a field object
    PROXIED_ATTRS = (
        # methods
        'get_value',
        'get_initial',
        'run_validation',
        'get_attribute',
        'to_representation',

        # attributes
        'field_name',
        'source',
        'read_only',
        'default',
        'source_attrs',
        'write_only',
    )

    def __init__(self, to=None, **kwargs):
        self.to = to
        self.init_kwargs = kwargs
        self._proxied = None

        super_kwargs = dict(
            (key, kwargs[key])
            for key in kwargs
            if key in _signature_parameters(serializers.Field.__init__)
        )
        super(RecursiveField, self).__init__(**super_kwargs)

    def bind(self, field_name, parent):
        # Extra-lazy binding, because when we are nested in a ListField, the
        # RecursiveField will be bound before the ListField is bound
        self.bind_args = (field_name, parent)

    @property
    def proxied(self):
        if not self._proxied:
            if self.bind_args:
                field_name, parent = self.bind_args

                if hasattr(parent, 'child') and parent.child is self:
                    # RecursiveField nested inside of a ListField
                    parent_class = parent.parent.__class__
                else:
                    # RecursiveField directly inside a Serializer
                    parent_class = parent.__class__

                assert issubclass(parent_class, BaseSerializer)

                if self.to is None:
                    proxied_class = parent_class
                else:
                    try:
                        module_name, class_name = self.to.rsplit('.', 1)
                    except ValueError:
                        module_name, class_name = parent_class.__module__, self.to

                    try:
                        proxied_class = getattr(
                            importlib.import_module(module_name), class_name)
                    except Exception as e:
                        raise ImportError(
                            'could not locate serializer %s' % self.to, e)

                # Create a new serializer instance and proxy it
                proxied = proxied_class(**self.init_kwargs)
                proxied.bind(field_name, parent)
                self._proxied = proxied

        return self._proxied

    def __getattribute__(self, name):
        if name in RecursiveField.PROXIED_ATTRS:
            try:
                proxied = object.__getattribute__(self, 'proxied')
                return getattr(proxied, name)
            except AttributeError:
                pass

        return object.__getattribute__(self, name)