import unittest
from django.test.client import Client
from djoauth.models import Consumer
from django.core.urlresolvers import reverse
import oauth2
import cgi


class TemporaryCredentialTestCase(unittest.TestCase):

    def setUp(self):
        self.consumer = Consumer.objects.create(
           name='Test Consumer', key='test', secret='test')

    def tearDown(self):
        self.consumer.delete()

    def testRequestCredentialGet(self):
        # Create consumer
        consumer = oauth2.Consumer(self.consumer.key, self.consumer.secret)

        # Create Client

        # Make request.
        client = oauth2.Client(consumer)
        c = Client()
        req = oauth2.Request.from_consumer_and_token(
            client.consumer, http_method='GET',
            http_url='http://testserver' + reverse('djoauth_request_token'))
        req.sign_request(client.method, client.consumer, client.token)
        response = c.get(req.to_url())

        self.assertEqual(response.status_code, 200)

        token = cgi.parse_qs(response.content)
        self.assertTrue('oauth_token' in token)
        self.assertTrue('oauth_token_secret' in token)
        self.assertTrue('oauth_callback_confirmed' in token)


    def testRequestCredentialPost(self):

        # Create consumer
        consumer = oauth2.Consumer(self.consumer.key, self.consumer.secret)

        # Make request.
        client = oauth2.Client(consumer)
        c = Client()
        req = oauth2.Request.from_consumer_and_token(
            client.consumer, http_method='POST',
            http_url='http://testserver' + reverse('djoauth_request_token'))
        req.sign_request(client.method, client.consumer, client.token)
        response = c.post(
            'http://testserver' + reverse('djoauth_request_token'), req)

        self.assertEqual(response.status_code, 200)

        token = cgi.parse_qs(response.content)
        self.assertTrue('oauth_token' in token)
        self.assertTrue('oauth_token_secret' in token)
        self.assertTrue('oauth_callback_confirmed' in token)

