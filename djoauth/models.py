from django.db import models
from django.db.models.signals import pre_save
from random import randint


class Consumer(models.Model):

    # Consumer's name
    name = models.CharField(max_length=200)

    # Consumer's key
    key = models.CharField(max_length=100)

    # Consumer's secret
    secret = models.CharField(max_length=100)


class Token(models.Model):

    # Timestamp.
    timestamp = models.DateTimeField(auto_now_add=True)

    # Is temporary.
    is_temporary = models.BooleanField(default=True)

    # Key
    key = models.CharField(max_length=100, unique=True)

    # Secret
    secret = models.CharField(max_length=100)

    def __init__(self):
        super(Token, self).__init__()
        self.key = self.make_random_string()
        self.secret = self.make_random_string()

    @staticmethod
    def make_random_string(length=32):
        origin = 'abcdefghijklmnopqrstuvwxyz0123456789'
        dest = [origin[randint(0, len(origin) - 1)] for i in range(length)]
        return ''.join(dest)
