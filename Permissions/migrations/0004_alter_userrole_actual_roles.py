# Generated by Django 4.1.2 on 2024-04-04 17:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Permissions', '0003_userrole_actual_roles'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userrole',
            name='actual_roles',
            field=models.BooleanField(default=False),
        ),
    ]
