# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-06-13 03:22
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auser', '0008_auto_20170613_0941'),
    ]

    operations = [
        migrations.AlterField(
            model_name='assest',
            name='cpu_num',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='assest',
            name='hdd_num',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='assest',
            name='ipaddr',
            field=models.CharField(max_length=200, unique=True),
        ),
        migrations.AlterField(
            model_name='assest',
            name='mem_info',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
