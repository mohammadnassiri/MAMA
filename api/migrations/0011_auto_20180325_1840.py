# Generated by Django 2.0.3 on 2018-03-25 14:10

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_record_vbox'),
    ]

    operations = [
        migrations.AlterField(
            model_name='record',
            name='created_time',
            field=models.DateTimeField(default=datetime.datetime(2018, 3, 25, 14, 10, 18, 405400, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='record',
            name='updated_time',
            field=models.DateTimeField(default=datetime.datetime(2018, 3, 25, 14, 10, 18, 405400, tzinfo=utc)),
        ),
    ]
