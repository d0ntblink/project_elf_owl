# Generated by Django 5.0.3 on 2024-03-22 03:12

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DependenciesMap',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dependencies_json', models.TextField()),
                ('dependencies_cve_vuln_found_json', models.TextField(null=True)),
                ('magik_hash', models.TextField(unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='InformationMap',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_name', models.TextField()),
                ('dataflow_json', models.TextField(null=True)),
                ('owasp_top10_json', models.TextField(null=True)),
                ('ai_bp_recommendations_json', models.TextField(null=True)),
                ('ai_security_recommendations_json', models.TextField(null=True)),
                ('cfg_image_relative_location', models.TextField(null=True)),
                ('secrets_found_json', models.TextField(null=True)),
                ('magik_hash', models.TextField(unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Repository',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('repo_name', models.TextField()),
                ('repo_origin', models.TextField()),
                ('repo_branch', models.TextField()),
                ('repo_location', models.TextField(unique=True)),
                ('added_by', models.TextField()),
                ('added_on', models.DateTimeField(auto_now_add=True)),
                ('last_synced_by', models.TextField(null=True)),
                ('last_synced_on', models.DateTimeField(null=True)),
                ('last_commit_msg', models.TextField(null=True)),
                ('last_commit_short_hash', models.TextField(null=True)),
                ('magik_hash', models.TextField(unique=True)),
            ],
        ),
    ]
