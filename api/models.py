from django.db import models
from datetime import datetime


class Record(models.Model):
    name = models.CharField(max_length=255, unique=True)
    arch = models.CharField(max_length=255)
    response = models.TextField()
    path = models.FileField(upload_to="dataset")
    sequence = models.TextField()
    run_pe_file = models.FileField(upload_to="extracted")
    run_pe_sequence = models.TextField()
    screen_shot = models.FileField(upload_to="screenshot")
    malware = models.BooleanField(default=False)
    run_pe = models.BooleanField(default=False)
    status = models.IntegerField(default=0)  # 0=waiting, 1=on process, 2=traced, 3=error
    vbox = models.CharField(max_length=255)
    created_time = models.DateTimeField(default=datetime.now)
    updated_time = models.DateTimeField(default=datetime.now)


class Vbox(models.Model):
    name = models.CharField(max_length=255, unique=True)
    status = models.IntegerField(default=0)  # 0=idle, 1=running, 2=complete-idle, 3=error not use
    time = models.DateTimeField(default=datetime.now)

