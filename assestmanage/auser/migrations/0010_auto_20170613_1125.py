# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-06-13 03:25
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auser', '0009_auto_20170613_1122'),
    ]

    operations = [
        migrations.AlterField(
            model_name='assest',
            name='hdd_type',
            field=models.CharField(choices=[('hdd', 'HDD'), ('ssd', 'SSD')], default='hdd', max_length=3),
        ),
    ]