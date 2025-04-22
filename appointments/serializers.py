from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Appointment, PatientProfile, AppointmentConfig
from datetime import date, datetime, time


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['username', 'password']

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = User.objects.filter(username=data['username']).first()
        if user and user.check_password(data['password']):
            refresh = RefreshToken.for_user(user)
            return {'refresh': str(refresh), 'access': str(refresh.access_token)}
        raise serializers.ValidationError("Invalid credentials")


class AppointmentSerializer(serializers.ModelSerializer):
    """Serializer for handling appointment data"""
    department = serializers.CharField(default="General Medicine")
    doctor = serializers.CharField(default="Unassigned")
    sex = serializers.ChoiceField(choices=Appointment.SEX_CHOICES)

    class Meta:
        model = Appointment
        fields = ['id', 'name', 'age', 'sex', 'date', 'time', 'department', 'doctor', 'token_number', 'payment_id', 'payment_status']
        read_only_fields = ['token_number', 'payment_id', 'payment_status']

    def validate(self, data):
        """Full validation of appointment data"""
        # Get configuration
        config = AppointmentConfig.objects.first()
        if not config:
            config = AppointmentConfig.objects.create()
        
        # Validate date is not in the past
        if data['date'] < date.today():
            raise serializers.ValidationError({"date": "Appointment date cannot be in the past."})
            
        # Check if booking on Sunday
        if data['date'].weekday() == 6:  # 6 is Sunday
            raise serializers.ValidationError({"date": "Appointments are not available on Sundays."})
            
        # Check if time is during lunch break (1 PM to 2 PM)
        if data['time'].hour == 13:
            raise serializers.ValidationError({"time": "Appointments are not available during lunch break (1 PM to 2 PM)."})
        
        # Check daily appointment limit
        daily_count = Appointment.objects.filter(date=data['date']).count()
        if daily_count >= config.max_daily_appointments:
            raise serializers.ValidationError({"date": f"Maximum appointments ({config.max_daily_appointments}) for this day have been reached."})
        
        # Check hourly appointment limit
        start_hour_time = datetime.combine(data['date'], time(hour=data['time'].hour))
        end_hour_time = datetime.combine(data['date'], time(hour=data['time'].hour, minute=59, second=59))
        
        hourly_count = Appointment.objects.filter(
            date=data['date'],
            time__gte=time(hour=data['time'].hour),
            time__lte=time(hour=data['time'].hour, minute=59, second=59)
        ).count()
        
        if hourly_count >= config.max_per_hour:
            raise serializers.ValidationError({
                "time": f"Maximum appointments ({config.max_per_hour}) for this hour have been reached. Please select a different time."
            })
            
        return data

    def validate_date(self, value):
        """Ensure the appointment date is today or in the future"""
        if value < date.today():
            raise serializers.ValidationError("Appointment date cannot be in the past.")
        return value
    
# Profile management
class PatientProfileSerializer(serializers.ModelSerializer):
    """Serializer for patient profiles"""
    
    class Meta:
        model = PatientProfile
        fields = ['id', 'profile_name', 'patient_name', 'age', 'sex', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']
        
    def validate_profile_name(self, value):
        """Ensure profile_name is unique for this user"""
        user = self.context['request'].user
        
        if not self.instance:
            if PatientProfile.objects.filter(user=user, profile_name=value).exists():
                raise serializers.ValidationError("A profile with this name already exists.")
        else:
            if PatientProfile.objects.filter(user=user, profile_name=value).exclude(id=self.instance.id).exists():
                raise serializers.ValidationError("A profile with this name already exists.")
                
        return value

class AppointmentConfigSerializer(serializers.ModelSerializer):
    """Serializer for appointment configuration"""
    
    class Meta:
        model = AppointmentConfig
        fields = ['id', 'max_daily_appointments', 'max_per_hour', 'updated_at']
        read_only_fields = ['updated_at']