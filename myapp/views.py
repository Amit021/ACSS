from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect, get_object_or_404
from django.core.serializers.json import DjangoJSONEncoder
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponseRedirect
from .models import MoodRecord, SymptomRecord, DoctorPatientRelationship, CustomUser, DoctorFeedback, Feedback
from .forms import (RegisterForm, HallucinationsForm, FlatteningForm, AvolitionForm, 
                    DelusionsForm, ConcentrationMemoryForm, SocialCognitionForm, LoginForm, AssignDoctorForm, DoctorFeedbackForm, AddPatientForm)
import json
from django.core import serializers
from django.views.decorators.http import require_POST
from django.db.models import Count, Avg
from django.db.models.functions import TruncDate
from django import forms
from django.db import models
from django.utils.dateparse import parse_date 
from datetime import datetime, timedelta
from django.utils import timezone
from collections import defaultdict
from django.utils.dateformat import DateFormat
from django.utils import dateformat
from django.utils.html import escape



class DateFilterForm(forms.Form):
    start_date = forms.DateField(required=False, widget=forms.TextInput(attrs={'type': 'date'}))
    end_date = forms.DateField(required=False, widget=forms.TextInput(attrs={'type': 'date'}))

def landing(request):
    return render(request, 'landing.html')

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            if user.role == 'doctor':
                return redirect('doctor_dashboard')
            else:
                return redirect('select_mood')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                # Redirect based on role
                role = request.POST.get('role')
                if role == 'Doctor':
                    return redirect('doctor_dashboard')
                else:
                    return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('landing')
    
@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


@login_required
def show_mood_selection(request):
    return render(request, 'select_mood.html')

@require_POST
@login_required
def record_mood(request):
    try:
        mood = request.POST.get('mood', 'unknown')
        unusual_behavior = request.POST.get('unusual_behavior', 'No')

        if mood is None or mood == '':
            mood = 'unknown'

        MoodRecord.objects.create(user=request.user, mood_rating=mood, unusual_behavior=unusual_behavior)
        return redirect('view_statistics')
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def view_feedback(request):
    mood_records = MoodRecord.objects.filter(user=request.user).order_by('timestamp')
    serialized_records = json.dumps(list(mood_records.values()), cls=DjangoJSONEncoder)
    context = {
        'mood_records': serialized_records
    }
    return render(request, 'view_feedback.html', context)

@login_required
def api_mood_statistics(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if not start_date or not end_date:
        return JsonResponse({'error': 'Invalid or missing date parameters'}, status=400)

    start_date = timezone.make_aware(datetime.strptime(start_date, '%Y-%m-%d'))
    end_date = timezone.make_aware(datetime.strptime(end_date, '%Y-%m-%d')) + timezone.timedelta(days=1)

    mood_records = MoodRecord.objects.filter(timestamp__range=(start_date, end_date))
    mood_data = mood_records.values('mood_rating').annotate(count=models.Count('mood_rating'))

    return JsonResponse(list(mood_data), safe=False)

@login_required
def api_mood_feedback(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if not start_date or not end_date:
        return JsonResponse({'error': 'Invalid or missing date parameters'}, status=400)

    start_date = timezone.make_aware(datetime.strptime(start_date, '%Y-%m-%d'))
    end_date = timezone.make_aware(datetime.strptime(end_date, '%Y-%m-%d')) + timezone.timedelta(days=1)

    mood_records = MoodRecord.objects.filter(timestamp__range=(start_date, end_date))
    mood_feedback = mood_records.values('timestamp', 'mood_rating')

    return JsonResponse(list(mood_feedback), safe=False)



@login_required
def view_symptoms(request):
    user = request.user
    print(f"User: {user}, Role: {user.role}")

    if user.role == 'doctor':
        relationships = DoctorPatientRelationship.objects.filter(doctor=user)
        patient_ids = relationships.values_list('patient_id', flat=True)
        symptom_records = SymptomRecord.objects.filter(user_id__in=patient_ids).order_by('-timestamp')
    else:
        symptom_records = SymptomRecord.objects.filter(user=user).order_by('-timestamp')

    print(f"Fetched {len(symptom_records)} symptom records.")

    grouped_records = defaultdict(lambda: defaultdict(list))
    for record in symptom_records:
        local_timestamp = timezone.localtime(record.timestamp)  # Convert to local time
        date_str = DateFormat(local_timestamp).format('Y-m-d')
        time_str = DateFormat(local_timestamp).format('H:i:s')
        grouped_records[date_str][time_str].append(record)
        print(f"Record {record.id} grouped under {date_str} -> {time_str}")

    collapsible_html = ""
    for date, times in grouped_records.items():
        collapsible_html += f'<button type="button" class="collapsible">{date}</button>'
        collapsible_html += '<div class="content">'
        for time, records in times.items():
            collapsible_html += f'<button type="button" class="collapsible">{time}</button>'
            collapsible_html += '<div class="content"><ul class="symptom-list">'
            for record in records:
                if isinstance(record.mcq_answers, str):
                    try:
                        record.mcq_answers = json.loads(record.mcq_answers)
                    except json.JSONDecodeError:
                        record.mcq_answers = {}
                elif not isinstance(record.mcq_answers, dict):
                    record.mcq_answers = {}

                mcq_answers_html = "".join([f"<li>{key}: {value}</li>" for key, value in record.mcq_answers.items()])
                collapsible_html += f"""
                <li class="symptom-item">
                    <strong>Timestamp:</strong> {timezone.localtime(record.timestamp)}<br>
                    <strong>Symptom Type:</strong> {record.symptom_type}<br>
                    <strong>Description:</strong> {record.description}<br>
                    <strong>Severity:</strong> {record.severity}<br>
                    <strong>MCQ Answers:</strong>
                    <ul class="mcq-answer">{mcq_answers_html}</ul>
                </li>
                """
            collapsible_html += '</ul></div>'
        collapsible_html += '</div>'

    context = {
        'collapsible_html': collapsible_html,
        'user': user
    }
    return render(request, 'view_symptoms.html', context)


@login_required
def view_statistics(request):
    print('view_statistics function called')
    user = request.user  # Get the current logged-in user
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if not start_date or not end_date:
        print('No start date or end date provided, fetching all records for the current user')
        mood_statistics_data = MoodRecord.objects.filter(user=user).values('mood_rating').annotate(count=models.Count('mood_rating'))
        mood_feedback_data = MoodRecord.objects.filter(user=user).values('timestamp', 'mood_rating')
    else:
        print(f'Filtering records from {start_date} to {end_date}')
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
        
        # Make datetime objects timezone aware
        start_date = timezone.make_aware(start_date)
        end_date = timezone.make_aware(end_date + timedelta(days=1))

        mood_statistics_data = MoodRecord.objects.filter(user=user, timestamp__range=(start_date, end_date)).values('mood_rating').annotate(count=models.Count('mood_rating'))
        mood_feedback_data = MoodRecord.objects.filter(user=user, timestamp__range=(start_date, end_date)).values('timestamp', 'mood_rating')

    mood_statistics = list(mood_statistics_data)
    mood_feedback = list(mood_feedback_data)

    print('Mood statistics data:', mood_statistics)
    print('Mood feedback data:', mood_feedback)

    context = {
        'mood_statistics': json.dumps(mood_statistics, cls=DjangoJSONEncoder),
        'mood_feedback': json.dumps(mood_feedback, cls=DjangoJSONEncoder),
    }

    print('Rendering view_statistics.html with context')
    return render(request, 'view_statistics.html', context)
@login_required
def view_settings(request):
    return render(request, 'view_settings.html')

@login_required
def show_symptom_selection(request):
    if request.method == 'POST':
        forms = [
            ('hallucinations', HallucinationsForm(request.POST, prefix='hallucinations')),
            ('delusions', DelusionsForm(request.POST, prefix='delusions')),
            ('flattening', FlatteningForm(request.POST, prefix='flattening')),
            ('avolition', AvolitionForm(request.POST, prefix='avolition')),
            ('concentration_memory', ConcentrationMemoryForm(request.POST, prefix='concentration_memory')),
            ('social_cognition', SocialCognitionForm(request.POST, prefix='social_cognition'))
        ]

        for symptom_type, form in forms:
            if form.is_valid():
                instance = form.save(commit=False)
                instance.symptom_type = symptom_type
                instance.user = request.user
                instance.mcq_answers = json.dumps(form.cleaned_data)
                instance.save()
                print(f"Saved {symptom_type} form: {form.cleaned_data}")
            else:
                print(f"Form is invalid for {symptom_type}: {form.errors}")

        print("Redirecting to view_symptoms")
        return HttpResponseRedirect(reverse('view_symptoms'))

    else:
        forms = {
            'hallucinations_form': HallucinationsForm(prefix='hallucinations'),
            'delusions_form': DelusionsForm(prefix='delusions'),
            'flattening_form': FlatteningForm(prefix='flattening'),
            'avolition_form': AvolitionForm(prefix='avolition'),
            'concentration_memory_form': ConcentrationMemoryForm(prefix='concentration_memory'),
            'social_cognition_form': SocialCognitionForm(prefix='social_cognition')
        }
    return render(request, 'select_symptom.html', forms)


@login_required
def doctor_dashboard(request):
    user = request.user
    patients_data = {}

    if request.method == 'POST':
        form = AddPatientForm(request.POST)
        if form.is_valid():
            patient = form.cleaned_data['patient_username']
            DoctorPatientRelationship.objects.create(doctor=user, patient=patient)
            return redirect('doctor_dashboard')
    else:
        form = AddPatientForm()

    if user.role == 'doctor':
        relationships = DoctorPatientRelationship.objects.filter(doctor=user)
        patient_ids = relationships.values_list('patient_id', flat=True)
        for patient_id in patient_ids:
            patient = CustomUser.objects.get(id=patient_id)
            symptom_records = SymptomRecord.objects.filter(user=patient).order_by('-timestamp')
            patients_data[patient.username] = {
                'patient': patient,
                'records': symptom_records
            }
    else:
        patient = user
        symptom_records = SymptomRecord.objects.filter(user=patient).order_by('-timestamp')
        patients_data[patient.username] = {
            'patient': patient,
            'records': symptom_records
        }

    context = {
        'patients_data': patients_data,
        'form': form
    }
    return render(request, 'doctor_dashboard.html', context)


@login_required
def add_feedback(request, patient_id):
    if request.user.role != 'doctor':
        return redirect('view_symptoms')

    patient = get_object_or_404(CustomUser, id=patient_id)
    if request.method == 'POST':
        form = DoctorFeedbackForm(request.POST)
        if form.is_valid():
            feedback = form.save(commit=False)
            feedback.doctor = request.user
            feedback.patient = patient
            feedback.save()
            return redirect('doctor_dashboard')
    else:
        form = DoctorFeedbackForm()
    
    return render(request, 'add_feedback.html', {'form': form, 'patient': patient})

@csrf_exempt
@login_required
def record_symptom(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            symptoms_data = data.get('symptoms', {})

            for symptom_type, details in symptoms_data.items():
                description = details.get('description', '')
                severity = details.get('severity', 0)
                mcq_answers = details.get('mcq_answers', {})

                symptom = SymptomRecord.objects.create(
                    user=request.user,
                    symptom_type=symptom_type,
                    description=description,
                    severity=severity,
                    mcq_answers=mcq_answers
                )
                symptom.save()

            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)




@login_required
def send_symptoms_to_doctor(request):
    print("send_symptoms_to_doctor view called")
    
    patient = request.user

    # Check if the patient has an assigned doctor
    try:
        relationship = DoctorPatientRelationship.objects.get(patient=patient)
    except DoctorPatientRelationship.DoesNotExist:
        print("No doctor assigned")
        return render(request, 'error.html', {'message': 'Sorry! No doctor has added you yet.'})

    # If the doctor is assigned, proceed with sending symptoms
    doctor = relationship.doctor
    symptom_records = SymptomRecord.objects.filter(user=patient).order_by('timestamp')
    
    data = []
    for record in symptom_records:
        data.append({
            'timestamp': record.timestamp.isoformat(),
            'symptom_type': record.symptom_type,
            'description': record.description,
            'severity': record.severity,
            'mcq_answers': record.mcq_answers,
        })
    
    request.session['sent_symptoms_data'] = data
    
    print("Symptoms data sent to doctor successfully")
    return render(request, 'success.html', {'message': 'Symptoms data sent to doctor successfully.'})



@login_required
def add_patient(request):
    if request.user.role != 'doctor':
        return redirect('view_symptoms')

    if request.method == 'POST':
        form = AddPatientForm(request.POST)
        if form.is_valid():
            patient = form.cleaned_data['patient_username']
            DoctorPatientRelationship.get_or_create_relationship(doctor=request.user, patient=patient)
            return redirect('doctor_dashboard')
    else:
        form = AddPatientForm()
    
    return render(request, 'add_patient.html', {'form': form})


@login_required
def submit_feedback(request):
    if request.method == 'POST':
        form = DoctorFeedbackForm(request.POST)
        if form.is_valid():
            feedback = form.save(commit=False)
            feedback.doctor = request.user
            feedback.save()
            return redirect('doctor_dashboard')
    else:
        form = DoctorFeedbackForm()
    return render(request, 'submit_feedback.html', {'form': form})
