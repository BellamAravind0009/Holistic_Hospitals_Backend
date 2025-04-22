from django.urls import path
from .views import (
    RegisterView, LoginView, ProtectedView,
    CreateAppointmentView, UpdateAppointmentView, ViewAppointmentsView, CancelAppointmentView,
    create_razorpay_order, verify_payment, PatientProfileView, PatientProfileDetailView, 
    GetProfileForAppointmentView, AppointmentConfigView,
)

urlpatterns = [
    # Authentication routes
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('protected/', ProtectedView.as_view(), name='protected'),

    # Appointment routes
    path('appointments/create/', CreateAppointmentView.as_view(), name='create-appointment'),
    path('appointments/update/', UpdateAppointmentView.as_view(), name='update-appointment'),
    path('appointments/view/', ViewAppointmentsView.as_view(), name='view-appointment'),
    path('appointments/cancel/<int:pk>/', CancelAppointmentView.as_view(), name='cancel-appointment'),
    
    # Appointment configuration
    path('appointments/config/', AppointmentConfigView.as_view(), name='appointment-config'),

    # Payment routes
    path("create-order/", create_razorpay_order, name="create-razorpay-order"),
    path("verify-payment/", verify_payment, name="verify-payment"),

    # Patient Profile routes
    path('profiles/', PatientProfileView.as_view(), name='patient-profiles'),
    path('profiles/<str:profile_name>/', PatientProfileDetailView.as_view(), name='patient-profile-detail'),
    path('profiles/appointment/<str:profile_name>/', GetProfileForAppointmentView.as_view(), name='get-profile-for-appointment'),
]