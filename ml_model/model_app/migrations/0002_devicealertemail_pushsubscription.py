# Generated for SecureFlow — DeviceAlertEmail + PushSubscription

from django.db import migrations, models
import time


class Migration(migrations.Migration):

    dependencies = [
        ('model_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceAlertEmail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip',           models.CharField(max_length=45, blank=True)),
                ('mac',          models.CharField(max_length=17, blank=True)),
                ('label',        models.CharField(max_length=128, blank=True)),
                ('email',        models.EmailField()),
                ('min_severity', models.CharField(max_length=10, default='Medium')),
                ('enabled',      models.BooleanField(default=True)),
                ('created_at',   models.FloatField(default=time.time)),
            ],
            options={
                'ordering': ['ip', 'email'],
                'indexes': [
                    models.Index(fields=['ip'],      name='dae_ip_idx'),
                    models.Index(fields=['mac'],     name='dae_mac_idx'),
                    models.Index(fields=['enabled'], name='dae_enabled_idx'),
                ],
            },
        ),
        migrations.CreateModel(
            name='PushSubscription',
            fields=[
                ('id',          models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('endpoint',    models.TextField(unique=True)),
                ('p256dh',      models.TextField()),
                ('auth',        models.TextField()),
                ('user_agent',  models.CharField(max_length=255, blank=True)),
                ('created_at',  models.FloatField(default=time.time)),
                ('last_used_at',models.FloatField(default=time.time)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
