# Generated by Django 2.0.3 on 2018-03-26 22:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_auto_20180325_1415'),
    ]

    operations = [
        migrations.RenameField(
            model_name='record',
            old_name='file',
            new_name='path',
        ),
    ]