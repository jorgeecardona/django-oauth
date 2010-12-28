import logging
import hmac
import hashlib
import base64
import string
from models import Consumer, Token
from django import forms


class AuthenticatedRequest(forms.Form):
    """
    This forms validate an authenticated request.

    Based on: http://tools.ietf.org/html/rfc5849#section-3.1

    """
    oauth_consumer_key = forms.CharField()

    oauth_token = forms.CharField(required=False)

    SIGNATURE_METHODS_CHOICES = (
        ('HMAC-SHA1', ""),
        ('RSA-SHA1', ""),
        ('PLAINTEXT', ""),
        )
    oauth_signature_method = forms.ChoiceField(
        choices=SIGNATURE_METHODS_CHOICES)

    oauth_timestamp = forms.IntegerField(min_value=0, required=False)

    oauth_nonce = forms.CharField(required=False)

    oauth_version = forms.CharField(required=False)

    oauth_signature = forms.CharField(required=True)

    def __init__(self, request):
        if request.method == 'GET':
            data = request.GET
        if request.method == 'POST':
            data = request.POST

        self._request = request
        super(AuthenticatedRequest, self).__init__(data=data)

    def clean_oauth_consumer_key(self):
        try:
            self.consumer = Consumer.objects.get(
                key=self.cleaned_data['oauth_consumer_key'])
        except Consumer.DoesNotExist, e:
            logging.error(e)
            raise forms.ValidationError("Consumer Not Found.")
        return self.cleaned_data['oauth_consumer_key']

    def clean_oauth_token(self):
        if 'oauth_token' not in self.data:
            self.token = None
            return None

        try:
            return Token.objects.get(key=self.cleaned_data['oauth_token'])
        except Token.DoesNotExist, e:
            logging.error(e)
            raise forms.ValidationError("Token Not Found.")

    def clean_oauth_timestamp(self):
        if self.cleaned_data['oauth_signature_method'] != 'PLAINTEXT':
            return None

        if 'oauth_timestamp' not in self.data:
            raise forms.ValidationError("Timestamp Not Found.")

        return self.cleaned_data['oauth_timestamp']

    def clean_oauth_nonce(self):
        if self.cleaned_data['oauth_signature_method'] != 'PLAINTEXT':
            return None

        if 'oauth_nonce' not in self.data:
            raise forms.ValidationError("Nonce Not Found.")

        return self.cleaned_data['oauth_nonce']

    def clean_oauth_version(self):
        if 'oauth_version' not in self.data:
            return '1.0'

        if self.cleaned_data['oauth_version'] != '1.0':
            raise forms.ValidationError("Invalid version.")

        return '1.0'

    def clean(self):
        # Check signature.
        method = self.cleaned_data['oauth_signature_method']

        if method == 'HMAC-SHA1':
            if self._hmac_sha1_signature():
                return self.cleaned_data

            raise forms.ValidationError("Signature Fail.")

        raise forms.ValidationError("Invalid Signature Method.")

    def _hmac_sha1_signature(self):
        # Get base string
        base_string = self.get_base_string()

        # Get consumer.
        key = '%s&' % (self._quote(self.consumer.secret), )
        if self.token:
            key += self._quote(self.token.secret, )

        # Signature
        signature = base64.encodestring(
            hmac.new(str(key), str(base_string), hashlib.sha1).digest())
        signature = signature[:-1]

        # Compare signatures
        return self.cleaned_data['oauth_signature'] == signature

    def get_base_string(self):
        # Build base_string
        base_components = [self._request.method]

        # URI
        base_components.append(self._quote(
            self._request.build_absolute_uri(self._request.path)))

        # Parameters
        base_components.append(self._normalize_parameters())

        # Build base_string
        base_string = '&'.join(base_components)

        return base_string

    @staticmethod
    def _quote(origin):
        dest = []
        for i in origin:
            if i in string.ascii_letters + string.digits + '-._~':
                dest.append(i)
            else:
                dest.append('%%%02X' % (ord(i), ))
        return ''.join(dest)

    def _normalize_parameters(self):

        # Collect parameters.
        parameters = {}

        # Method parameters
        if self._request.method == 'GET':
            parameters.update(self._request.GET)
        elif self._request.method == 'POST':
            parameters.update(self._request.POST)
        
        parameters.pop('oauth_signature')

        parameters_normalized = []

        for key in parameters:
            for value in parameters[key]:
                parameters_normalized.append(
                    (self._quote(key), self._quote(value)))

        # Sort parameters.
        parameters_normalized.sort(key=lambda x: x[0] + x[1])
        parameters_normalized = [
            '='.join(item) for item in parameters_normalized]
        parameters_normalized = "&".join(parameters_normalized)

        return self._quote(parameters_normalized)

    def save(self):
        return Token.objects.create()


class TemporaryCredential(AuthenticatedRequest):
    """
    This forms validate a temporary credential request.

    Based on: http://tools.ietf.org/html/rfc5849#section-2.1
    """

    oauth_callback = forms.CharField(required=False)

