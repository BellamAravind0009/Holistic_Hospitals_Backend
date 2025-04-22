from django.contrib.auth.models import User
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404
from .serializers import RegisterSerializer, LoginSerializer, AppointmentSerializer,PatientProfileSerializer,AppointmentConfigSerializer
from .models import Appointment,PatientProfile,AppointmentConfig
from datetime import date,time
import razorpay
from razorpay.errors import BadRequestError, ServerError
from django.conf import settings
from django.http import JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from razorpay.errors import BadRequestError, ServerError
from django.core.cache import cache
from django.http import HttpResponseForbidden
import uuid
import json
import logging
from rest_framework.pagination import PageNumberPagination
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.db import transaction
from .models import Appointment, PatientProfile, AppointmentConfig, TransactionLog
from django.core.cache import cache
from django.db.models import Prefetch, Count, Q
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page



logger = logging.getLogger('payment.transactions')

logger = logging.getLogger(__name__)



def rate_limit_payment_requests(user_id, max_attempts=5, timeout=300):
    """Rate limit payment attempts to prevent brute force attacks"""
    cache_key = f"payment_attempts_{user_id}"
    attempts = cache.get(cache_key, 0)
    
    if attempts >= max_attempts:
        return False
    
    cache.set(cache_key, attempts + 1, timeout)
    return True

# **1. User Authentication**
class RegisterView(generics.CreateAPIView):
    """User registration"""
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

class LoginView(APIView):
    """User login to obtain JWT tokens"""
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    """Protected API endpoint"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You have access!"})

# **2. Appointment Management**



@method_decorator(cache_page(60*15), name='dispatch')  # Cache for 15 minutes
class AppointmentConfigView(generics.RetrieveUpdateAPIView):
    """View for getting and updating appointment configuration"""
    serializer_class = AppointmentConfigSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        # Get the first config or create a default one
        config, created = AppointmentConfig.objects.get_or_create(id=1)
        return config
    

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100
    

class CreateAppointmentView(generics.CreateAPIView):
    """Create new appointment and auto-assign token"""
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        selected_date = serializer.validated_data['date']
        selected_time = serializer.validated_data['time']

        # Check if appointment date is not in the past
        if selected_date < date.today():
            raise serializer.ValidationError({"date": "Cannot book appointments for past dates."})

        # Check if date is Sunday
        if selected_date.weekday() == 6:
            raise serializer.ValidationError({"date": "Appointments are not available on Sundays."})
            
        # Check lunch break
        if selected_time.hour == 13:
            raise serializer.ValidationError({"time": "Appointments are not available during lunch break (1 PM to 2 PM)."})

        # Get configuration
        config = AppointmentConfig.objects.first()
        if not config:
            config = AppointmentConfig.objects.create()

        # Check daily appointment limit
        daily_count = Appointment.objects.filter(date=selected_date).count()
        if daily_count >= config.max_daily_appointments:
            raise serializer.ValidationError(
                {"date": f"Maximum appointments ({config.max_daily_appointments}) for this day have been reached."}
            )
            
        # Check hourly appointment limit
        start_hour_time = time(hour=selected_time.hour)
        end_hour_time = time(hour=selected_time.hour, minute=59, second=59)
        
        hourly_count = Appointment.objects.filter(
            date=selected_date,
            time__gte=start_hour_time,
            time__lte=end_hour_time
        ).count()
        
        if hourly_count >= config.max_per_hour:
            raise serializer.ValidationError({
                "time": f"Maximum appointments ({config.max_per_hour}) for this hour have been reached. Please select a different time."
            })

        # Use transaction to prevent race conditions
        from django.db import transaction
        with transaction.atomic():
            # Count all appointments on the selected date
            existing_appointments = Appointment.objects.filter(date=selected_date).count()
            token_number = existing_appointments + 1

            # Assign the logged-in user to the appointment
            serializer.save(user=self.request.user, token_number=token_number)

class UpdateAppointmentView(APIView):
    """Update appointment date and reassign token"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request):
        appointment_id = request.data.get('id')
        new_date_str = request.data.get('date')
        new_time_str = request.data.get('time')

        if not appointment_id or not new_date_str or not new_time_str:
            return Response({"error": "Appointment ID, new date, and new time are required"}, 
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get appointment
            appointment = get_object_or_404(Appointment, id=appointment_id, user=request.user)
            
            # Convert string to date and time objects
            from datetime import datetime
            new_date = datetime.strptime(new_date_str, '%Y-%m-%d').date()
            new_time = datetime.strptime(new_time_str, '%H:%M').time()
            
            # Validate date and time
            if new_date < date.today():
                return Response({"error": "Appointment date cannot be in the past"}, 
                                status=status.HTTP_400_BAD_REQUEST)
                                
            # Check if date is Sunday
            if new_date.weekday() == 6:
                return Response({"error": "Appointments are not available on Sundays"}, 
                                status=status.HTTP_400_BAD_REQUEST)
                                
            # Check lunch break
            if new_time.hour == 13:
                return Response({"error": "Appointments are not available during lunch break (1 PM to 2 PM)"}, 
                                status=status.HTTP_400_BAD_REQUEST)
                
            # Get configuration
            config = AppointmentConfig.objects.first()
            if not config:
                config = AppointmentConfig.objects.create()
                
            # Check if there are any changes
            if appointment.date == new_date and appointment.time == new_time:
                return Response({"message": "No changes made", "appointment": AppointmentSerializer(appointment).data}, 
                                status=status.HTTP_200_OK)
                
            # Check daily appointment limit
            daily_count = Appointment.objects.filter(date=new_date).exclude(id=appointment_id).count()
            if daily_count >= config.max_daily_appointments:
                return Response(
                    {"error": f"Maximum appointments ({config.max_daily_appointments}) for this day have been reached"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check hourly appointment limit
            start_hour_time = time(hour=new_time.hour)
            end_hour_time = time(hour=new_time.hour, minute=59, second=59)
            
            hourly_count = Appointment.objects.filter(
                date=new_date,
                time__gte=start_hour_time,
                time__lte=end_hour_time
            ).exclude(id=appointment_id).count()
            
            if hourly_count >= config.max_per_hour:
                return Response({
                    "error": f"Maximum appointments for this hour have been reached. Please select a different time."
                }, status=status.HTTP_400_BAD_REQUEST)
            
        except ValueError:
            return Response({"error": "Invalid date or time format. Use YYYY-MM-DD for date and HH:MM for time"}, 
                            status=status.HTTP_400_BAD_REQUEST)

        # Use transaction to prevent race conditions when updating token
        from django.db import transaction
        with transaction.atomic():
            # Store the old date and token number before updating
            old_date = appointment.date
            old_token_number = appointment.token_number
            
            # Check if the date is changing
            if appointment.date != new_date:
                # If the date is changing, we need to reassign the token number for the new date
                highest_token = Appointment.objects.filter(date=new_date).order_by('-token_number').first()
                # If there are appointments on the new date, get the highest token and add 1
                # If no appointments exist for the new date, set token_number to 1
                new_token_number = (highest_token.token_number + 1) if highest_token else 1
                appointment.token_number = new_token_number
                
                # Find all appointments on the old date with token numbers higher than this appointment
                # and decrease their token numbers by 1 to close the gap
                appointments_to_update = Appointment.objects.filter(
                    date=old_date,
                    token_number__gt=old_token_number
                ).order_by('token_number')
                
                # Update token numbers for all affected appointments
                for affected_appointment in appointments_to_update:
                    affected_appointment.token_number -= 1
                    affected_appointment.save()
                
            # Update the appointment's date and time
            appointment.date = new_date
            appointment.time = new_time
            appointment.save()

        return Response({
            "message": "Appointment updated successfully",
            "appointment": AppointmentSerializer(appointment).data
        }, status=status.HTTP_200_OK)
        
    


class ViewAppointmentsView(generics.ListAPIView):
    """View only the logged-in user's appointments"""
    serializer_class = AppointmentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        queryset = Appointment.objects.filter(user=self.request.user)
        
        # Add filtering options
        date_filter = self.request.query_params.get('date', None)
        if date_filter:
            queryset = queryset.filter(date=date_filter)
        
        # Add name filter for finding appointments by name
        name_filter = self.request.query_params.get('name', None)
        if name_filter:
            queryset = queryset.filter(name__icontains=name_filter)
            
        # Add ordering for better performance and user experience
        return queryset.order_by('-date', 'time')



# **3. Payment Integration**
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def create_razorpay_order(request):
    """Create a Razorpay order but do NOT finalize booking yet"""
    try:
        # Apply rate limiting
        if not rate_limit_payment_requests(request.user.id):
            return JsonResponse({"error": "Too many payment attempts. Please try again later."}, status=429)
            
        amount = request.data.get("amount")
        appointment_id = request.data.get("appointment_id")

        if not amount or not str(amount).isdigit() or int(amount) <= 0:
            return JsonResponse({"error": "Invalid amount"}, status=400)

        if not appointment_id:
            return JsonResponse({"error": "Appointment ID is required"}, status=400)

        # Add idempotency key support
        idempotency_key = request.headers.get('X-Idempotency-Key')
        if idempotency_key:
            # Check if this key was already used
            cache_key = f"idempotency_{request.user.id}_{idempotency_key}"
            if cache.get(cache_key):
                return JsonResponse({"error": "Duplicate request detected"}, status=400)
            
            # Store the key with an expiration
            cache.set(cache_key, True, 86400)  # 24 hour expiration

        try:
            appointment = get_object_or_404(Appointment, id=appointment_id, user=request.user)
        except:
            return JsonResponse({"error": "Invalid appointment"}, status=404)

        # Check if payment is already in progress or completed
        if appointment.payment_status == "Paid":
            return JsonResponse({"error": "Appointment is already paid for"}, status=400)

        amount = int(amount) * 100  # Convert to paise
        currency = "INR"

        # Log transaction start
        transaction_data = {
            "user_id": request.user.id,
            "appointment_id": appointment_id,
            "amount": amount/100,  # Convert back for logging
            "status": "INITIATED"
        }
        logger.info(f"Payment initiated: {json.dumps(transaction_data)}")

        try:
            razorpay_order = razorpay_client.order.create({
                "amount": amount,
                "currency": currency,
                "payment_capture": "1"
            })
        except BadRequestError as e:
            logger.error(f"Razorpay error: {str(e)}")
            return JsonResponse({"error": f"Razorpay error: {str(e)}"}, status=400)
        except ServerError as e:
            logger.error(f"Razorpay server error: {str(e)}")
            return JsonResponse({"error": "Razorpay server error. Please try again later."}, status=503)

        # Store order ID but DO NOT finalize booking yet
        appointment.payment_id = razorpay_order.get("id")
        appointment.payment_status = "Pending"
        appointment.save()

        # Log successful order creation
        logger.info(f"Razorpay order created: {razorpay_order.get('id')}")

        return JsonResponse({
            "order_id": razorpay_order.get("id", ""),
            "amount": amount,
            "currency": currency,
            "status": razorpay_order.get("status", "failed")
        })

    except Exception as e:
        logger.error(f"Error in create_razorpay_order: {str(e)}")
        return JsonResponse({"error": "An unexpected error occurred. Please try again."}, status=500)

@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_payment(request):
    """Verify Razorpay payment with improved transaction handling"""
    transaction_log = None
    try:
        order_id = request.data.get("order_id")
        payment_id = request.data.get("payment_id")
        signature = request.data.get("signature")
        
        if not order_id or not payment_id or not signature:
            return JsonResponse({"error": "Missing payment details"}, status=400)
        
        # Start a transaction log
        transaction_log = TransactionLog.objects.create(
            user=request.user,
            payment_provider="Razorpay",
            status="INITIATED",
            amount=500.00,  # Replace with actual appointment fee
            request_data=request.data
        )
        
        try:
            # Get appointment within a transaction
            with transaction.atomic():
                appointment = get_object_or_404(
                    Appointment, 
                    payment_id=order_id, 
                    user=request.user
                )
                
                # Update transaction log
                transaction_log.appointment = appointment
                transaction_log.save()
                
                # Verify payment using Razorpay SDK
                params_dict = {
                    'razorpay_order_id': order_id,
                    'razorpay_payment_id': payment_id,
                    'razorpay_signature': signature
                }
                
                try:
                    # Verify signature
                    razorpay_client.utility.verify_payment_signature(params_dict)
                    
                    # Update appointment status
                    appointment.payment_status = "Paid"
                    appointment.save()
                    
                    # Update transaction log
                    transaction_log.status = "COMPLETED"
                    transaction_log.payment_id = payment_id
                    transaction_log.response_data = {"status": "success"}
                    transaction_log.save()
                    
                    logger.info(f"Payment successful: {payment_id} for appointment {appointment.id}")
                    
                    # Return appointment details for the confirmation page
                    appointment_data = {
                        "name": appointment.name,
                        "age": appointment.age,
                        "date": appointment.date,
                        "department": appointment.department,
                        "doctor": appointment.doctor,
                        "token_number": appointment.token_number,
                    }
                    
                    return JsonResponse({
                        "message": "Payment successful", 
                        "appointment": appointment_data,
                        "transaction_id": str(transaction_log.transaction_id)
                    }, status=200)
                    
                except razorpay.errors.SignatureVerificationError:
                    transaction_log.status = "FAILED"
                    transaction_log.response_data = {"error": "Signature verification failed"}
                    transaction_log.save()
                    logger.warning(f"Payment signature verification failed: {payment_id}")
                    return JsonResponse({"error": "Payment verification failed"}, status=400)
                    
        except Exception as e:
            transaction_log.status = "ERROR"
            transaction_log.response_data = {"error": str(e)}
            transaction_log.save()
            logger.error(f"Payment verification error: {str(e)}")
            return JsonResponse({"error": f"Error processing payment: {str(e)}"}, status=500)
            
    except Exception as e:
        if transaction_log:
            transaction_log.status = "ERROR"
            transaction_log.response_data = {"error": str(e)}
            transaction_log.save()
        logger.error(f"Unhandled payment error: {str(e)}")
        return JsonResponse({"error": "Payment processing failed"}, status=500)

#profile management 


class PatientProfileView(generics.ListCreateAPIView):
    """Create and list patient profiles"""
    serializer_class = PatientProfileSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return PatientProfile.objects.filter(user=self.request.user)
        
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class PatientProfileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a patient profile using profile_name"""
    serializer_class = PatientProfileSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'profile_name'  
    
    def get_queryset(self):
        return PatientProfile.objects.filter(user=self.request.user)

class GetProfileForAppointmentView(APIView):
    """Fetch profile data for use in appointment booking using profile_name"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, profile_name):
        try:
            profile = PatientProfile.objects.get(profile_name=profile_name, user=request.user)
            return Response({
                "name": profile.patient_name,
                "age": profile.age,
                "sex": profile.sex
            }, status=status.HTTP_200_OK)
        except PatientProfile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)
        


class CancelAppointmentView(generics.DestroyAPIView):
    """Cancel an appointment"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = Appointment.objects.all()
    
    def get_queryset(self):
        # Ensure users can only cancel their own appointments
        return Appointment.objects.filter(user=self.request.user)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # Check if appointment is in the past
        if instance.date < date.today():
            return Response(
                {"error": "Cannot cancel past appointments"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if appointment is today
        if instance.date == date.today():
            # You might want to add additional logic here
            # For example, not allowing cancellation if it's too close to the appointment time
            pass
            
        # Perform the deletion
        self.perform_destroy(instance)
        return Response(
            {"message": "Appointment cancelled successfully"}, 
            status=status.HTTP_200_OK
        )
    
