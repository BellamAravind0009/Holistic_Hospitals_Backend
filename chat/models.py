# hospital_assistant/models.py
from django.db import models
from django.contrib.auth.models import User

class ChatSession(models.Model):
    """Stores chat sessions for the hospital assistant"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_sessions')
    session_id = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_interaction = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Chat Session: {self.user.username} - {self.created_at}"

class ChatMessage(models.Model):
    """Stores individual chat messages"""
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='messages')
    is_user = models.BooleanField(default=True)  # True if message is from user, False if from assistant
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['timestamp']
    
    def __str__(self):
        return f"{'User' if self.is_user else 'Assistant'}: {self.message[:30]}..."