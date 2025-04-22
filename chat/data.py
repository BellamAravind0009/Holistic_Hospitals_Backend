# hospital_assistant/data.py

# Sample symptom data - expand as needed
SYMPTOM_DATA = {
    "headache": {
        "possible_conditions": ["Tension headache", "Migraine", "Sinusitis"],
        "recommendation": "If severe or persistent, consult a doctor. Rest in a quiet, dark room and stay hydrated."
    },
    "fever": {
        "possible_conditions": ["Common cold", "Flu", "Infection"],
        "recommendation": "Monitor temperature. If above 103°F (39.4°C) or persists for more than 3 days, consult a doctor."
    },
    "cough": {
        "possible_conditions": ["Common cold", "Allergies", "Bronchitis"],
        "recommendation": "Stay hydrated. If persistent for more than a week or producing colored phlegm, consult a doctor."
    },
    "chest pain": {
        "possible_conditions": ["Angina", "Heart attack", "Muscle strain", "GERD"],
        "recommendation": "SEEK IMMEDIATE MEDICAL ATTENTION if severe, especially if accompanied by shortness of breath, nausea, or pain radiating to arm/jaw."
    },
    "shortness of breath": {
        "possible_conditions": ["Asthma", "Anxiety", "Heart failure", "COVID-19"],
        "recommendation": "SEEK IMMEDIATE MEDICAL ATTENTION if severe or sudden onset."
    },
    "abdominal pain": {
        "possible_conditions": ["Gastritis", "Appendicitis", "Food poisoning", "IBS"],
        "recommendation": "If severe, persistent, or accompanied by fever, seek medical attention. Mild cases may be monitored."
    },
    "nausea": {
        "possible_conditions": ["Food poisoning", "Stomach virus", "Migraine", "Medication side effect"],
        "recommendation": "Stay hydrated. If persistent or accompanied by severe vomiting, seek medical attention."
    },
    "dizziness": {
        "possible_conditions": ["Low blood pressure", "Dehydration", "Inner ear issues", "Anemia"],
        "recommendation": "Sit or lie down immediately. If persistent or recurrent, consult a doctor."
    },
    "fatigue": {
        "possible_conditions": ["Anemia", "Depression", "Hypothyroidism", "Sleep disorders"],
        "recommendation": "If persistent for more than two weeks despite adequate rest, consult a doctor."
    },
    "rash": {
        "possible_conditions": ["Allergic reaction", "Eczema", "Contact dermatitis"],
        "recommendation": "Avoid scratching. If spreading rapidly or accompanied by difficulty breathing, seek immediate medical attention."
    }
}

# Hospital schedule data
HOSPITAL_SCHEDULE = {
    "general_hours": {
        "monday": "8:00 AM - 8:00 PM",
        "tuesday": "8:00 AM - 8:00 PM",
        "wednesday": "8:00 AM - 8:00 PM",
        "thursday": "8:00 AM - 8:00 PM",
        "friday": "8:00 AM - 8:00 PM",
        "saturday": "9:00 AM - 6:00 PM",
        "sunday": "9:00 AM - 2:00 PM (Emergency services only)"
    },
    "departments": {
        "Cardiology": {
            "schedule": {
                "monday": "9:00 AM - 5:00 PM",
                "tuesday": "9:00 AM - 5:00 PM",
                "wednesday": "9:00 AM - 5:00 PM",
                "thursday": "9:00 AM - 5:00 PM",
                "friday": "9:00 AM - 5:00 PM",
                "saturday": "10:00 AM - 2:00 PM",
                "sunday": "Closed"
            },
            "doctors": ["Dr. Sharma", "Dr. Patel", "Dr. Gupta"]
        },
        "Orthopedics": {
            "schedule": {
                "monday": "10:00 AM - 6:00 PM",
                "tuesday": "10:00 AM - 6:00 PM",
                "wednesday": "10:00 AM - 6:00 PM",
                "thursday": "10:00 AM - 6:00 PM",
                "friday": "10:00 AM - 6:00 PM",
                "saturday": "10:00 AM - 2:00 PM",
                "sunday": "Closed"
            },
            "doctors": ["Dr. Singh", "Dr. Verma", "Dr. Kumar"]
        },
        "Pediatrics": {
            "schedule": {
                "monday": "9:00 AM - 6:00 PM",
                "tuesday": "9:00 AM - 6:00 PM",
                "wednesday": "9:00 AM - 6:00 PM",
                "thursday": "9:00 AM - 6:00 PM",
                "friday": "9:00 AM - 6:00 PM",
                "saturday": "9:00 AM - 4:00 PM",
                "sunday": "Closed"
            },
            "doctors": ["Dr. Joshi", "Dr. Malhotra", "Dr. Bhat"]
        },
        "Dermatology": {
            "schedule": {
                "monday": "10:00 AM - 5:00 PM",
                "tuesday": "10:00 AM - 5:00 PM",
                "wednesday": "10:00 AM - 5:00 PM",
                "thursday": "10:00 AM - 5:00 PM",
                "friday": "10:00 AM - 5:00 PM",
                "saturday": "10:00 AM - 2:00 PM",
                "sunday": "Closed"
            },
            "doctors": ["Dr. Reddy", "Dr. Agarwal"]
        },
        "Emergency": {
            "schedule": {
                "monday": "24 hours",
                "tuesday": "24 hours",
                "wednesday": "24 hours",
                "thursday": "24 hours",
                "friday": "24 hours",
                "saturday": "24 hours",
                "sunday": "24 hours"
            },
            "doctors": ["On-call emergency physicians"]
        }
    }
}