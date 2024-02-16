from django.db import models


class CA(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    organization = models.TextField()
    cn = models.TextField()
    key = models.TextField()
    cert = models.TextField()

    def __str__(self):
        return self.name


class Server(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    organization = models.TextField()
    cn = models.TextField()
    key = models.TextField()
    cert = models.TextField()
    ca = models.ForeignKey(CA, on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class Client(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    organization = models.TextField()
    cn = models.TextField()
    user_id = models.TextField()
    key = models.TextField()
    cert = models.TextField()
    server = models.ForeignKey(Server, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
