# Generated by Django 5.1.7 on 2025-03-17 19:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('appointments', '0003_appointment_payment_id_appointment_payment_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='appointment',
            name='doctor',
            field=models.CharField(default='General', max_length=255),
        ),
    ]
