# Generated by Django 4.2.20 on 2025-04-10 09:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AdminApp', '0002_verificationtestfile'),
    ]

    operations = [
        migrations.CreateModel(
            name='EncryptionPerformance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_name', models.CharField(max_length=255)),
                ('file_size', models.FloatField()),
                ('mkhe_encryption_time', models.FloatField()),
                ('mkhe_decryption_time', models.FloatField()),
                ('mkhe_key_size', models.IntegerField()),
                ('ecc_encryption_time', models.FloatField()),
                ('ecc_decryption_time', models.FloatField()),
                ('ecc_key_size', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.DeleteModel(
            name='VerificationTestFile',
        ),
    ]
