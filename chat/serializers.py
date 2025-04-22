# hospital_assistant/serializers.py
from rest_framework import serializers
from .models import ChatSession, ChatMessage

class ChatMessageSerializer(serializers.ModelSerializer):
    """Serializer for chat messages"""
    class Meta:
        model = ChatMessage
        fields = ['id', 'is_user', 'message', 'timestamp']
        read_only_fields = ['id', 'timestamp']

class ChatSessionSerializer(serializers.ModelSerializer):
    """Serializer for chat sessions"""
    messages = ChatMessageSerializer(many=True, read_only=True)
    
    class Meta:
        model = ChatSession
        fields = ['id', 'session_id', 'created_at', 'last_interaction', 'messages']
        read_only_fields = ['id', 'created_at', 'last_interaction']

class ChatRequestSerializer(serializers.Serializer):
    """Serializer for chat request"""
    message = serializers.CharField(required=True)
    session_id = serializers.CharField(required=False, allow_blank=True)
    
    def validate_message(self, value):
        """Validate that the message is not empty"""
        if not value.strip():
            raise serializers.ValidationError("Message cannot be empty")
        return value
        
class ChatResponseSerializer(serializers.Serializer):
    """Serializer for chat response"""
    response = serializers.CharField()
    session_id = serializers.CharField()