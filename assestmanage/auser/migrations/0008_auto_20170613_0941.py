# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-06-13 01:41
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auser', '0007_auto_20170613_0940'),
    ]

    operations = [
        migrations.AlterField(
            model_name='assest',
            name='passwd_key',
            field=models.CharField(max_length=200),
        ),
        migrations.AlterField(
            model_name='assest',
            name='port',
            field=models.CharField(max_length=100),
        ),
    ]
