# Generated by Django 2.0.3 on 2018-04-03 08:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_option_power'),
    ]

    operations = [
        migrations.AlterField(
            model_name='record',
            name='sequence',
            field=models.FileField(upload_to='sequence'),
        ),
    ]