# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-06-10 03:43
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auser', '0002_username_passwd'),
    ]

    operations = [
        migrations.AlterField(
            model_name='username',
            name='passwd',
            field=models.CharField(max_length=200),
        ),
    ]
