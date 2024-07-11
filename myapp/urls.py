from django.urls import path, include
from django.contrib.auth import views as auth_views
from . import views


urlpatterns = [
    path('', views.landing, name='landing'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('select_mood/', views.show_mood_selection, name='select_mood'),
    path('record_mood/', views.record_mood, name='record_mood'),
    path('view_statistics/', views.view_statistics, name='view_statistics'),
    path('view_feedback/', views.view_feedback, name='view_feedback'),
    path('api/mood_statistics/', views.api_mood_statistics, name='api_mood_statistics'),
    path('api/mood_feedback/', views.api_mood_feedback, name='api_mood_feedback'),
    path('view_settings/', views.view_settings, name='view_settings'),
    path('select_symptom/', views.show_symptom_selection, name='select_symptom'),
    path('view_symptoms/', views.view_symptoms, name='view_symptoms'),
    path('doctor_dashboard/', views.doctor_dashboard, name='doctor_dashboard'),
    path('add_feedback/<int:patient_id>/', views.add_feedback, name='add_feedback'),
    path('record_symptom/', views.record_symptom, name='record_symptom'),
    path('send_symptoms_to_doctor/', views.send_symptoms_to_doctor, name='send_symptoms_to_doctor'),
    
    path('add_patient/', views.add_patient, name='add_patient'),
    path('submit_feedback/', views.submit_feedback, name='submit_feedback'),
    path('dashboard/', views.dashboard, name='dashboard'), 
    
]
