# Generated by Django 4.1.2 on 2024-04-15 17:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Account', '0002_userprofile_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='birth_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='city',
            field=models.CharField(blank=True, max_length=60, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='state',
            field=models.CharField(blank=True, max_length=60, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='zip',
            field=models.CharField(blank=True, max_length=60, null=True),
        ),
    ]