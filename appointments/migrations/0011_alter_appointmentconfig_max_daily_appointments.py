# Generated by Django 5.1.7 on 2025-04-22 16:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('appointments', '0010_transactionlog_appointment_updated_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appointmentconfig',
            name='max_daily_appointments',
            field=models.PositiveIntegerField(default=30),
        ),
    ]
