# Generated by Django 5.0.7 on 2024-07-24 17:19

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Request',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('method', models.CharField(max_length=10)),
                ('payload', models.TextField()),
                ('headers', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.TextField()),
                ('start_time', models.DateTimeField(auto_now=True)),
                ('end_time', models.DateTimeField(null=True)),
                ('scanner_ip', models.CharField(max_length=45)),
            ],
        ),
        migrations.CreateModel(
            name='Response',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status_code', models.IntegerField()),
                ('headers', models.TextField()),
                ('content', models.TextField()),
                ('request', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.request')),
            ],
        ),
        migrations.CreateModel(
            name='Scan_Url',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_url', models.TextField()),
                ('status_code', models.IntegerField()),
                ('headers', models.TextField()),
                ('html_content', models.TextField()),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.scan')),
            ],
        ),
        migrations.AddField(
            model_name='request',
            name='scan_url',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.scan_url'),
        ),
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(max_length=50)),
                ('description', models.TextField()),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], max_length=10)),
                ('recommendation', models.TextField(null=True)),
                ('cvss', models.FloatField(null=True)),
                ('cve', models.TextField(null=True)),
                ('proof_of_concept', models.TextField(null=True)),
                ('scan_url', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.scan_url')),
            ],
        ),
    ]
