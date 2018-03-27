# Generated by Django 2.0.3 on 2018-03-27 11:14

import datetime
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_auto_20180325_1415'),
    ]

    operations = [
        migrations.CreateModel(
            name='Vbox',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('status', models.IntegerField(default=0)),
                ('time', models.DateTimeField(default=datetime.datetime.now)),
            ],
        ),
        migrations.RenameField(
            model_name='record',
            old_name='file',
            new_name='path',
        ),
        migrations.AlterField(
            model_name='record',
            name='vbox',
            field=models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.Vbox'),
        ),
    ]
