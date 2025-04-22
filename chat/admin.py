# hospital_assistant/admin.py
from django.contrib import admin
from .models import ChatSession, ChatMessage

class ChatMessageInline(admin.TabularInline):
    model = ChatMessage
    extra = 0
    readonly_fields = ['timestamp']

@admin.register(ChatSession)
class ChatSessionAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'session_id', 'created_at', 'last_interaction']
    search_fields = ['user__username', 'session_id']
    readonly_fields = ['created_at', 'last_interaction']
    inlines = [ChatMessageInline]

@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'session', 'is_user', 'short_message', 'timestamp']
    list_filter = ['is_user', 'timestamp']
    search_fields = ['message', 'session__user__username']
    readonly_fields = ['timestamp']
    
    def short_message(self, obj):
        return obj.message[:50] + ('...' if len(obj.message) > 50 else '')
    short_message.short_description = 'Message'