# hospital_assistant/urls.py
from django.urls import path
from .views import ChatView, ChatHistoryView

urlpatterns = [
    path('api/chat/', ChatView.as_view(), name='chat-api'),
    path('api/chat-history/', ChatHistoryView.as_view(), name='chat-history'),
]