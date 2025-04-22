# hospital_assistant/gemini_assistant.py
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import google.generativeai as genai
from dotenv import load_dotenv
from django.conf import settings

# Load environment variables from .env file
load_dotenv()

# Initialize Gemini client
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

class HospitalChatAssistant:
    def __init__(self, knowledge_base_text):
        # Split the knowledge base into chunks for better retrieval
        self.chunks = self._chunk_text(knowledge_base_text)
        
        # Create a vectorizer and embeddings for the chunks
        self.vectorizer = TfidfVectorizer()
        self.chunk_embeddings = self.vectorizer.fit_transform(self.chunks)
        
        # Additional context for the assistant
        self.context = {
            "consultation_fee": 500,
            "currency": "₹",
            "payment_methods": ["Pay Now (Razorpay UPI)", "Pay Later"],
            "hospital_name": "Your Hospital Name"
        }
        
        # Initialize the Gemini model
        self.model = genai.GenerativeModel('gemini-1.5-pro')
    
    def _chunk_text(self, text, max_chunk_size=300):
        """Split text into smaller chunks for better retrieval"""
        paragraphs = text.split('\n\n')
        chunks = []
        
        current_chunk = ""
        for para in paragraphs:
            if len(current_chunk) + len(para) < max_chunk_size:
                current_chunk += para + "\n\n"
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                current_chunk = para + "\n\n"
                
        if current_chunk:
            chunks.append(current_chunk.strip())
            
        return chunks
    
    def _retrieve_relevant_chunks(self, query, top_k=3):
        """Find the most relevant chunks for the given query"""
        # Convert query to vector using the same vectorizer
        query_vector = self.vectorizer.transform([query])
        
        # Calculate similarity scores
        similarity_scores = cosine_similarity(query_vector, self.chunk_embeddings)[0]
        
        # Get indices of top k chunks
        top_indices = np.argsort(similarity_scores)[-top_k:][::-1]
        
        # Return top chunks and their scores
        return [(self.chunks[i], similarity_scores[i]) for i in top_indices if similarity_scores[i] > 0.1]
    
    def generate_response(self, query, chat_history=None):
        """Generate a response using Gemini based on the query and retrieved information"""
        # Initialize chat history if not provided
        if chat_history is None:
            chat_history = []
        
        # Retrieve relevant chunks from knowledge base
        relevant_chunks = self._retrieve_relevant_chunks(query)
        
        # If no relevant information found
        if not relevant_chunks:
            context_info = "I don't have specific information about that in my knowledge base."
        else:
            # Combine the relevant chunks into context
            context_info = "\n\n".join([chunk for chunk, score in relevant_chunks])
        
        # Keep just recent history to avoid token limits
        if len(chat_history) > 4:  # Keep just the last 2 exchanges
            chat_history = chat_history[-4:]
        
        # Construct the prompt for Gemini
        system_prompt = f"""You are a helpful hospital appointment assistant. 
You help patients with booking appointments, understanding payment options, and other hospital-related queries.
Use ONLY the following context to answer the user's question. If the information is not in the context, 
politely say you don't have that specific information and offer to help with related topics you do know about.

CONTEXT INFORMATION:
{context_info}

Additional system information:
- Consultation fee: {self.context['currency']}{self.context['consultation_fee']}
- Payment methods: {', '.join(self.context['payment_methods'])}
- Hospital Name: {self.context['hospital_name']}

Be concise, friendly, and helpful in your responses."""
        
        try:
            # Start a fresh chat
            chat = self.model.start_chat(history=[])
            
            # Add system prompt as first message
            chat.send_message(f"System: {system_prompt}")
            
            # Add conversation history
            for i in range(0, len(chat_history), 2):
                if i+1 < len(chat_history):
                    # Add user message and assistant response as context
                    chat.send_message(f"User: {chat_history[i]}")
                    chat.send_message(f"Assistant: {chat_history[i+1]}")
            
            # Send the user query
            response = chat.send_message(query)
            
            # Extract the assistant's reply
            assistant_reply = response.text
            
            return assistant_reply
            
        except Exception as e:
            # Handle API errors gracefully
            print(f"Error calling Gemini API: {e}")
            return "I'm sorry, I encountered an error while generating a response. Please try again."

# Load knowledge base function
def load_knowledge_base():
    try:
        import os
        knowledge_base_path = os.path.join(settings.BASE_DIR, 'hospital_assistant', 'knowledge_base.txt')
        with open(knowledge_base_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        # Fallback knowledge base
        return """Hospital Appointment Booking Assistant - Knowledge Base
System Overview:
This assistant is designed to help patients and hospital staff interact
seamlessly with the hospital appointment booking system, which has been
developed using Django and PostgreSQL for the backend and React,
Bootstrap, and Lucide for the frontend. The system facilitates features
such as booking appointments, viewing doctor schedules, processing
payments, and tracking token numbers for patient visits.

Frequently Asked Questions (FAQs):
1. How do I book an appointment?
To book an appointment, log in to the system first. Once logged in,
navigate to the "Book Appointment" section. From there, you can select a
doctor, choose your preferred date and time, and select a payment method
- either Pay Now or Pay Later.

2. What happens after booking?
After successfully booking an appointment, the system assigns you a
unique token number. This number is based on the current day's queue and
will be displayed immediately upon confirming or skipping the payment
process.

3. What are the payment options?
You can choose between two payment options: Pay Now or Pay Later. If you
select Pay Now, you will be redirected to a Razorpay UPI payment
interface. If you select Pay Later, your appointment will be booked
without processing a payment at that moment.

4. What is the consultation fee?
The standard consultation fee is ₹500. This fee is displayed clearly
during the appointment booking process.

5. How do I check my token number?
Your token number will be shown after a successful appointment booking.
It is also accessible in the "My Appointments" section for your
reference.

6. Can I view or cancel my appointments?
Yes. After logging in, go to the "View Appointments" page to see a
list of your scheduled appointments. Options for canceling or
rescheduling can be implemented as needed.

7. How do I know which doctors are available?
When booking an appointment, the system automatically shows you the list
of doctors and their available slots based on current scheduling data.

8. What time should I arrive for my appointment?
To ensure a smooth experience, it is recommended to arrive at least
15-20 minutes before your token number is expected to be called."""