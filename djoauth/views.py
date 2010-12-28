from django.http import HttpResponse, HttpResponseForbidden
from forms import TemporaryCredential
from urllib import urlencode


def request_token(request):
    """
    This view request a temporary token.
    """

    form = TemporaryCredential(request=request)
    if form.is_valid():
        temporary_token = form.save()
        response = {
            'oauth_token': temporary_token.key,
            'oauth_token_secret': temporary_token.secret,
            'oauth_callback_confirmed': 'true'}

        return HttpResponse(
            content=urlencode(response),
            content_type='application/x-www-form-urlencoded')
    else:
        return HttpResponseForbidden('')

def authorize(request):
    pass

def access_token(request):
    pass
