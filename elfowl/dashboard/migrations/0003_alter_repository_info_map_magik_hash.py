# Generated by Django 5.0.3 on 2024-03-22 04:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0002_rename_repository_repositories_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='repository_info_map',
            name='magik_hash',
            field=models.TextField(null=True),
        ),
    ]
