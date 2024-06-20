from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Profile
from .email_llama3 import generate_email, bhashini_translate,generate_bus_pro, generate_offer_letter, generate_summary, generate_content, generate_sales_script  
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from .models import PasswordResetRequest
from django.core.mail import send_mail, BadHeaderError
from datetime import datetime
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
import json
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.http import require_POST
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken


def generate_otp():
    return get_random_string(length=6, allowed_chars='0123456789')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return render(request, 'forgot_password.html', {'error': 'Email does not exist'})

        # Generate OTP
        otp = generate_otp()
        expiry_time = timezone.now() + timedelta(minutes=10)

        # Store OTP and expiry time in the database
        PasswordResetRequest.objects.create(user=user, otp=otp, expiry_time=expiry_time)

        # Send OTP via email
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is {otp}. This OTP is valid only for 10 minutes.'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except BadHeaderError:
            return render(request, 'forgot_password.html', {'error': 'Invalid header found.'})
        except Exception as e:
            return render(request, 'forgot_password.html', {'error': f'Error sending email: {str(e)}'})

        return redirect('reset_password')

    return render(request, 'forgot_password.html')

def landing(request):
    return render(request, 'landing.html')

def about(request):
    return render(request, 'about.html')

# @csrf_exempt
# def signin(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)
#             email = data.get('email')
#             password = data.get('password')
            
#             try:
#                 user = User.objects.get(email=email)
#                 username = user.username
#             except User.DoesNotExist:
#                 return JsonResponse({'error': 'Invalid email or password'}, status=400)
            
#             user = authenticate(request, username=username, password=password)
#             if user is not None:
#                 login(request, user)
#                 return JsonResponse({'success': 'User authenticated'}, status=200)
#             else:
#                 return JsonResponse({'error': 'Invalid email or password'}, status=400)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=500)
#     return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def signin(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            try:
                user = User.objects.get(email=email)
                username = user.username
            except User.DoesNotExist:
                return JsonResponse({'error': 'Invalid email or password'}, status=400)

            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return JsonResponse({
                    'success': 'User authenticated',
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }, status=200)
            else:
                return JsonResponse({'error': 'Invalid email or password'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)
        
def reset_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        otp = request.POST['otp']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        # handle reset password logic
        return redirect('signin')
    return render(request, 'reset_password.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

@csrf_exempt
@login_required
def email_generator(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            purpose = data.get('purpose')
            if purpose == 'others':
                purpose = data.get('purpose_other')
            num_words = data.get('num_words')
            subject = data.get('subject')
            rephrase = data.get('rephrase', False)
            to = data.get('to')
            tone = data.get('tone')
            keywords = [data.get(f'keyword_{i}') for i in range(1, 9)]
            contextual_background = data.get('contextual_background')
            call_to_action = data.get('call_to_action')
            if call_to_action == 'others':
                call_to_action = data.get('call_to_action_other')
            additional_details = data.get('additional_details')
            priority_level = data.get('priority_level')
            closing_remarks = data.get('closing_remarks')

            generated_content = generate_email(
                purpose, num_words, subject, rephrase, to, tone, keywords,
                contextual_background, call_to_action, additional_details,
                priority_level, closing_remarks
            )

            return JsonResponse({'generated_content': generated_content}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)




# @csrf_exempt
# @login_required
# def email_generator(request):
#     if request.method == 'POST':
#         try:
#             purpose = request.POST.get('purpose')
#             if purpose == 'others':
#                 purpose = request.POST.get('purpose_other')
#             num_words = request.POST.get('num_words')
#             subject = request.POST.get('subject')
#             rephrase = 'rephrase' in request.POST
#             to = request.POST.get('to')
#             tone = request.POST.get('tone')
#             keywords = [request.POST.get(f'keyword_{i}') for i in range(1, 9)]
#             contextual_background = request.POST.get('contextual_background')
#             call_to_action = request.POST.get('call_to_action')
#             if call_to_action == 'others':
#                 call_to_action = request.POST.get('call_to_action_other')
#             additional_details = request.POST.get('additional_details')
#             priority_level = request.POST.get('priority_level')
#             closing_remarks = request.POST.get('closing_remarks')

#             generated_content = generate_email(purpose, num_words, subject, rephrase, to, tone, keywords, contextual_background, call_to_action, additional_details, priority_level, closing_remarks)
#             return render(request, 'generated_content.html', {'generated_content': generated_content})
#         except Exception as e:
#             return render(request, 'generated_content.html', {'error': e})

#     return render(request, 'email_generator.html')

@csrf_exempt
@login_required
def translate_content(request):
    translated_content = None
    error = None
    language = ""

    if request.method == 'POST':
        generated_content = request.POST.get('generated_content')
        print(generated_content)
        language = request.POST.get('language')
        print(language)
        response = bhashini_translate(generated_content, language)
        if response["status_code"] == 200:
            translated_content = response["translated_content"]
            return render(request, 'generated_content.html', {
                'generated_content': generated_content,
                'translated_content': translated_content,
                'selected_language': language
            })
        else:
            error = response #"Translation failed:" 
    else:
        error = "Form Submission Failed"  # Debugging
    return render(request, 'generated_content.html', {
                'generated_content': generated_content,
                'translated_content': translated_content,
                'selected_language': language,
                'error': error,
            })



@csrf_exempt
def translate(request):
    translated_text = None
    error = None
    input_text = ""
    from_language = ""
    to_language = ""

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            input_text = data.get('input_text', '')
            from_language = data.get('from_language', '')
            to_language = data.get('to_language', '')

            if input_text and from_language and to_language:
                try:
                    # Replace this with your translation function call
                    translated_text = bhashini_translate(input_text, to_language, from_language)
                    translated_text = translated_text["translated_content"]
                    print(input_text, from_language, to_language)
                except Exception as e:
                    error = f"Error during translation: {str(e)}"
            else:
                error = "Please provide the input text and select both languages."
        except json.JSONDecodeError:
            error = "Invalid JSON format received."

    return JsonResponse({
        'translated_text': translated_text,
        'error': error,
        'input_text': input_text,
        'from_language': from_language,
        'to_language': to_language
    })


@csrf_exempt
@login_required
def business_proposal_generator(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            business_intro = data.get('business_intro')
            proposal_objective = data.get('proposal_objective')
            num_words = data.get('num_words')
            scope_of_work = data.get('scope_of_work')
            project_phases = data.get('project_phases')
            expected_outcomes = data.get('expected_outcomes')
            innovative_approaches = data.get('innovative_approaches')
            technologies_used = data.get('technologies_used')
            target_audience = data.get('target_audience')
            budget_info = data.get('budget_info')
            timeline = data.get('timeline')
            benefits = data.get('benefits')
            closing_remarks = data.get('closing_remarks')

            proposal_content = generate_bus_pro(
                business_intro, proposal_objective, num_words, scope_of_work,
                project_phases, expected_outcomes, innovative_approaches,
                technologies_used, target_audience, budget_info, timeline,
                benefits, closing_remarks
            )

            return JsonResponse({'generated_content': proposal_content}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def offer_letter_generator(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            company_details = data.get('companyDetails')
            num_words = data.get('numberOfWords')
            candidate_name = data.get('candidateFullName')
            position_title = data.get('positionTitle')
            department = data.get('department')
            supervisor = data.get('supervisor')
            status = data.get('status')
            location = data.get('location')
            start_date = data.get('expectedStartDate')
            compensation = data.get('compensationPackage')
            benefits = data.get('benefits')
            work_hours = data.get('workHours')
            duration = data.get('duration')
            terms = data.get('termsConditions')
            acceptance_deadline = data.get('deadline')
            contact_info = data.get('contactInfo')
            documents_needed = data.get('documentsNeeded')
            closing_remarks = data.get('closingRemarks')

            offer_letter_content = generate_offer_letter(
                company_details, num_words, candidate_name, position_title, department, supervisor, status,
                location, start_date, compensation, benefits, work_hours, duration,
                terms, acceptance_deadline, contact_info, documents_needed, closing_remarks
            )

            return JsonResponse({'generated_content': offer_letter_content})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@login_required
def generated_content(request):
    return render(request, 'generated_content.html')

@login_required
def logout_view(request):
    logout(request)
    return redirect('signin')


@login_required
def profile(request):
    user = request.user
    profile = Profile.objects.get(user=user)
    errors = []

    if request.method == 'POST':
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        profile.bio = request.POST.get('bio')
        profile.location = request.POST.get('location')
        
        birth_date = request.POST.get('birth_date')
        if birth_date:
            try:
                profile.birth_date = datetime.strptime(birth_date, '%Y-%m-%d').date()
            except ValueError:
                errors.append("Invalid date format for birth date.")
                profile.birth_date = None

        if not user.first_name:
            errors.append("First name is required.")
        if not user.last_name:
            errors.append("Last name is required.")

        if not errors:
            user.save()
            profile.save()
            return redirect('profile')

    return render(request, 'profile.html', {'user': user, 'profile': profile, 'errors': errors})

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')

        if not request.user.check_password(current_password):
            return render(request, 'profile.html', {'user': request.user, 'profile': request.user.profile, 'errors': ['Current password is incorrect.']})

        if new_password != confirm_new_password:
            return render(request, 'profile.html', {'user': request.user, 'profile': request.user.profile, 'errors': ['New passwords do not match.']})

        if new_password == current_password:
            return render(request, 'profile.html', {'user': request.user, 'profile': request.user.profile, 'errors': ['New password cannot be the same as the current password.']})

        request.user.set_password(new_password)
        request.user.save()
        update_session_auth_hash(request, request.user)  # Important, to keep the user logged in
        return redirect('profile')

    return redirect('profile')

@csrf_exempt
@login_required
def summarize_document(request):
    if request.method == 'POST':
        document_context = request.POST.get('document_context')
        main_subject = request.POST.get('main_subject')
        summary_purpose = request.POST.get('summary_purpose')
        length_detail = request.POST.get('length_detail')
        important_elements = request.POST.get('important_elements')
        audience = request.POST.get('audience')
        tone = request.POST.get('tone')
        format = request.POST.get('format')
        additional_instructions = request.POST.get('additional_instructions')
        document = request.FILES.get('document')
        
        # Call the generate_summary function
        summary_content = generate_summary(
            document_context,
            main_subject,
            summary_purpose,
            length_detail,
            important_elements,
            audience,
            tone,
            format,
            additional_instructions,
            document
        )
        
        if summary_content:
            # Return JSON response with generated content
            return JsonResponse({'generated_content': summary_content})
        else:
            return JsonResponse({'error': 'Failed to generate summary. Please try again.'}, status=400)
    
    # Handle GET requests (if needed)
    return JsonResponse({'error': 'Method not allowed.'}, status=405)

@csrf_exempt
@login_required
def content_generator(request):
    if request.method == 'POST':
        # Parse JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        company_info = data.get('company_info')
        content_purpose = data.get('content_purpose')
        desired_action = data.get('desired_action')
        topic_details = data.get('topic_details')
        keywords = data.get('keywords')
        audience_profile = data.get('audience_profile')
        format_structure = data.get('format_structure')
        num_words = data.get('num_words')
        seo_keywords = data.get('seo_keywords')
        references = data.get('references')
        
        # Call the generate_content function
        content = generate_content(
            company_info,
            content_purpose,
            desired_action,
            topic_details,
            keywords,
            audience_profile,
            format_structure,
            num_words,
            seo_keywords,
            references
        )
        
        if content:
            return JsonResponse({'generated_content': content})
        else:
            return JsonResponse({'error': 'Failed to generate content. Please try again.'}, status=400)

    # Handle GET requests or other HTTP methods
    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
@login_required
def sales_script_generator(request):
    if request.method == 'POST':
        try:
            # Load JSON data from request body
            data = json.loads(request.body)

            # Extract data from JSON
            num_words = data.get('num_words')
            company_details = data.get('company_details')
            product_descriptions = data.get('product_descriptions')
            features_benefits = data.get('features_benefits')
            pricing_info = data.get('pricing_info')
            promotions = data.get('promotions')
            target_audience = data.get('target_audience')
            sales_objectives = data.get('sales_objectives')
            tone_style = data.get('tone_style')
            competitive_advantage = data.get('competitive_advantage')
            testimonials = data.get('testimonials')
            compliance = data.get('compliance')
            tech_integration = data.get('tech_integration')

            # Call the generate_sales_script function
            sales_script = generate_sales_script(
                company_details,
                num_words,
                product_descriptions,
                features_benefits,
                pricing_info,
                promotions,
                target_audience,
                sales_objectives,
                tone_style,
                competitive_advantage,
                testimonials,
                compliance,
                tech_integration
            )

            if sales_script:
                # Return JSON response with generated content
                return JsonResponse({'generated_content': sales_script})

            # Handle case where script generation failed
            messages.error(request, 'Failed to generate sales script. Please try again.')
            return JsonResponse({'error': 'Failed to generate sales script. Please try again.'}, status=500)

        except json.JSONDecodeError as e:
            # Handle JSON decode error
            messages.error(request, 'Invalid JSON format. Please provide valid JSON data.')
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)

    # Handle GET request or any other method
    return JsonResponse({'error': 'Method not allowed.'}, status=405)