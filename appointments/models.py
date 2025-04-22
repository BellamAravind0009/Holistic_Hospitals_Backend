from django.db import models
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import uuid
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
import re


class AppointmentConfig(models.Model):
    """Configuration for appointment limits and restrictions"""
    max_daily_appointments = models.PositiveIntegerField(default=4)
    max_per_hour = models.PositiveIntegerField(default=3)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Appointment Config (Last updated: {self.updated_at})"
    
    class Meta:
        verbose_name = "Appointment Configuration"
        verbose_name_plural = "Appointment Configurations"

# Add these imports at the top


# Add this function for name validation
def validate_name(value):
    """Validate that name contains only allowed characters"""
    if not re.match(r'^[A-Za-z\s\'-]+$', value):
        raise ValidationError('Name contains invalid characters')

# Then update your Appointment model
class Appointment(models.Model):
    SEX_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other')
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, validators=[validate_name])
    age = models.PositiveIntegerField(validators=[MinValueValidator(0), MaxValueValidator(120)])
    sex = models.CharField(max_length=1, choices=SEX_CHOICES, default='O')
    date = models.DateField()
    time = models.TimeField(default="09:00:00")
    department = models.CharField(max_length=255, default='General Medicine')
    doctor = models.CharField(max_length=255) 
    token_number = models.PositiveIntegerField(blank=True, null=True)
    payment_id = models.CharField(max_length=100, blank=True, null=True)
    payment_status = models.CharField(
        max_length=50, 
        choices=[("Pending", "Pending"), ("Processing", "Processing"), ("Paid", "Paid"), ("Failed", "Failed")], 
        default="Pending"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Track version for optimistic concurrency control
    version = models.IntegerField(default=0)
    
    class Meta:
        # Add indexes for frequently queried fields
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date', 'time']),
            models.Index(fields=['payment_status']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.date} {self.time} (Token: {self.token_number})"
    
    def clean(self):
        """Enhanced validation logic centralized in the model"""
        # Date validation
        from datetime import date
        if self.date < date.today():
            raise ValidationError({'date': 'Appointment date cannot be in the past'})
            
        # Check if date is Sunday
        if self.date.weekday() == 6:
            raise ValidationError({'date': 'Appointments are not available on Sundays'})
            
        # Time validation - Check lunch break
        if self.time.hour == 13:
            raise ValidationError({'time': 'Appointments are not available during lunch break (1 PM to 2 PM)'})
    
    def save(self, *args, **kwargs):
        self.full_clean()
        
        # Increment version for optimistic concurrency control
        if self.id:
            self.version += 1
            
        super().save(*args, **kwargs)


@receiver(pre_save, sender=Appointment)
def assign_token(sender, instance, **kwargs):
    if not instance.token_number:
        from django.db import transaction
        with transaction.atomic():
            # Get the highest token number for that date and increment
            highest_token = Appointment.objects.filter(date=instance.date).order_by('-token_number').first()
            instance.token_number = (highest_token.token_number + 1) if highest_token else 1


# Profile management
class PatientProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='patient_profiles')
    profile_name = models.CharField(max_length=100)  # A unique name to identify this profile
    patient_name = models.CharField(max_length=255)
    age = models.PositiveIntegerField()
    sex = models.CharField(max_length=1, choices=Appointment.SEX_CHOICES, default='O')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'profile_name']  # Ensure profile names are unique per user

    def __str__(self):
        return f"{self.profile_name} - {self.patient_name}"
    

class TransactionLog(models.Model):
    """Log for all payment transactions"""
    transaction_id = models.UUIDField(default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    appointment = models.ForeignKey(Appointment, on_delete=models.SET_NULL, null=True)
    payment_provider = models.CharField(max_length=50, default="Razorpay")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=50)
    payment_id = models.CharField(max_length=255, blank=True, null=True)
    request_data = models.JSONField(blank=True, null=True)
    response_data = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.transaction_id} - {self.status}"