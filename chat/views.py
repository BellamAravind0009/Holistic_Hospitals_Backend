# hospital_assistant/views.py
import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import ChatRequestSerializer, ChatResponseSerializer, ChatSessionSerializer
from .models import ChatSession, ChatMessage
from .gemini_assistant import HospitalChatAssistant, load_knowledge_base

# Load knowledge base
knowledge_base_text = load_knowledge_base()

# Initialize the assistant
assistant = HospitalChatAssistant(knowledge_base_text)

class ChatView(APIView):
    """
    API endpoint for interacting with the hospital chat assistant
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        # Validate request data
        serializer = ChatRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Get user message and session ID from request
        user_message = serializer.validated_data['message']
        session_id = serializer.validated_data.get('session_id', '')
        
        # Get or create chat session
        if session_id:
            try:
                chat_session = ChatSession.objects.get(
                    session_id=session_id, 
                    user=request.user
                )
            except ChatSession.DoesNotExist:
                # If session ID doesn't exist or belongs to another user, create new
                chat_session = ChatSession.objects.create(
                    user=request.user,
                    session_id=str(uuid.uuid4())
                )
        else:
            # Create new session if none specified
            chat_session = ChatSession.objects.create(
                user=request.user,
                session_id=str(uuid.uuid4())
            )
        
        # Save user message
        ChatMessage.objects.create(
            session=chat_session,
            is_user=True,
            message=user_message
        )
        
        # Get conversation history for this session
        chat_history = []
        for msg in chat_session.messages.all().order_by('timestamp'):
            chat_history.append(msg.message)
        
        # Generate response using the Gemini-powered assistant
        response = assistant.generate_response(user_message, chat_history)
        
        # Save assistant response
        ChatMessage.objects.create(
            session=chat_session,
            is_user=False,
            message=response
        )
        
        # Return the response
        response_data = {
            'response': response,
            'session_id': chat_session.session_id
        }
        
        return Response(response_data)

class ChatHistoryView(APIView):
    """
    API endpoint for retrieving chat history
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        # Get session ID from query parameters
        session_id = request.query_params.get('session_id', None)
        
        if session_id:
            # Get specific session
            try:
                chat_session = ChatSession.objects.get(
                    session_id=session_id, 
                    user=request.user
                )
                serializer = ChatSessionSerializer(chat_session)
                return Response(serializer.data)
            except ChatSession.DoesNotExist:
                return Response(
                    {"error": "Chat session not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Get all sessions for user
            chat_sessions = ChatSession.objects.filter(user=request.user).order_by('-last_interaction')
            serializer = ChatSessionSerializer(chat_sessions, many=True)
            return Response(serializer.data)