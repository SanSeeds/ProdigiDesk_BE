import random
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Profile
from .email_llama3 import generate_email, bhashini_translate,generate_bus_pro, generate_offer_letter, generate_summary, generate_content, generate_sales_script  
from django.contrib.auth.models import User
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
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.password_validation import validate_password  
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, renderer_classes
from rest_framework.renderers import BaseRenderer
from rest_framework.renderers import JSONRenderer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Base64-encoded AES IV and Secret Key
AES_IV_b64 = "KRP1pDpqmy2eJos035bxdg=="
AES_SECRET_KEY_b64 = "HOykfyW56Uesby8PTgxtSA=="
ENCRYPTION_IV_b64 = "3G1Nd0j0l5BdPmJh01NrYg=="
ENCRYPTION_SECRET_KEY_b64 = "XGp3hFq56Vdse3sLTtXyQQ=="

# Decode Base64 strings to bytes
AES_IV = base64.b64decode(AES_IV_b64)
AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY_b64)
ENCRYPTION_IV = base64.b64decode(ENCRYPTION_IV_b64)
ENCRYPTION_SECRET_KEY = base64.b64decode(ENCRYPTION_SECRET_KEY_b64)

# Decode Base64 strings to bytes
AES_IV = base64.b64decode(AES_IV_b64)
AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY_b64)

# Ensure IV is 16 bytes long (128 bits)
if len(AES_IV) != 16:
    raise ValueError("AES IV must be 16 bytes long")

print("AES IV:", AES_IV)
print(len(AES_IV))
print("AES Secret Key:", AES_SECRET_KEY)

class CustomAesRenderer(BaseRenderer):
    media_type = 'application/octet-stream'
    format = 'aes'

    def render(self, data, media_type=None, renderer_context=None):
        plaintext = json.dumps(data)
        padded_plaintext = pad(plaintext.encode(), 16)
        cipher = AES.new(AES_SECRET_KEY, AES.MODE_CBC, AES_IV)
        ciphertext = cipher.encrypt(padded_plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        response = {'ciphertext': ciphertext_b64}
        return json.dumps(response)


def encrypt_data(data):
    plaintext = json.dumps(data)
    padded_plaintext = pad(plaintext.encode(), 16)
    cipher = AES.new(ENCRYPTION_SECRET_KEY, AES.MODE_CBC, ENCRYPTION_IV)
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return ciphertext_b64

def decrypt_data(encrypted_data):
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(ENCRYPTION_SECRET_KEY, AES.MODE_CBC, ENCRYPTION_IV)
        decrypted_data = unpad(cipher.decrypt(encrypted_data_bytes), 16)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption error: {e}")


@csrf_exempt
def add_user(request):
    try:
        data = json.loads(request.body)

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            return JsonResponse({'error': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return JsonResponse({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(password)
        except ValidationError as e:
            return JsonResponse({'error': list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username is already taken.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        return JsonResponse({'success': 'User created successfully.'}, status=status.HTTP_201_CREATED)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format.'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def generate_otp():
    return ''.join(random.choices('0123456789', k=6))

@csrf_exempt
def send_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Email does not exist'}, status=404)

        # Generate OTP
        otp = generate_otp()
        expiry_time = timezone.now() + timedelta(minutes=10)

        # Store OTP and expiry time in the database
        PasswordResetRequest.objects.update_or_create(
            user=user,
            defaults={
                'otp': otp,
                'expiry_time': expiry_time
            }
        )

        # Send OTP via email
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is {otp}. This OTP is valid only for 10 minutes.'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except Exception as e:
            # Log the error for further analysis
            print(f"Error sending email: {str(e)}")
            return JsonResponse({'error': f'Error sending email: {str(e)}'}, status=500)

        return JsonResponse({'success': 'OTP sent successfully'}, status=200)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
@api_view(['POST'])
def forgot_password(request):
    data = json.loads(request.body)
    email = data.get('email')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({'error': 'Email does not exist'}, status=404)

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
        return JsonResponse({'error': 'Invalid header found.'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Error sending email: {str(e)}'}, status=500)

    return JsonResponse({'success': 'OTP sent successfully'}, status=200)

def landing(request):
    return render(request, 'landing.html')

def about(request):
    return render(request, 'about.html')


@csrf_exempt
def signin(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return JsonResponse({'error': 'Email and password are required'}, status=400)

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Invalid email or password'}, status=400)

            user = authenticate(request, username=user.username, password=password)
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
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            # Log the exception (consider using logging framework)
            return JsonResponse({'error': 'Internal server error'}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([email, otp, new_password, confirm_password]):
            return JsonResponse({'error': 'All fields are required'}, status=400)

        # Check if passwords match
        if new_password != confirm_password:
            return JsonResponse({'error': 'Passwords do not match'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User with this email does not exist'}, status=404)

        try:
            password_reset_request = PasswordResetRequest.objects.get(user=user, otp=otp)
        except PasswordResetRequest.DoesNotExist:
            return JsonResponse({'error': 'Invalid OTP'}, status=400)

        # Check if the OTP has expired
        if password_reset_request.expiry_time < timezone.now():
            return JsonResponse({'error': 'OTP has expired'}, status=400)

        # Update the user's password
        user.set_password(new_password)
        user.save()

        # Optionally delete the password reset request after successful reset
        password_reset_request.delete()

        return JsonResponse({'success': 'Password reset successfully'}, status=200)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def email_generator(request):
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

        if generated_content:
            # Send the email
            send_mail(
                subject,
                generated_content,
                settings.DEFAULT_FROM_EMAIL,
                [to],
                fail_silently=False,
            )

            # Encrypt the response content
            encrypted_content = encrypt_data({'generated_content': generated_content})

            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        return JsonResponse({'error': 'Failed to generate email. Please try again.'}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def translate_content(request):
    translated_content = None
    error = None
    language = ""

    if request.method == 'POST':
        try:
            data = request.data  # Assuming request body is in JSON format
            generated_content = data.get('generated_content')
            language = data.get('language')

            if not generated_content or not language:
                return JsonResponse({'error': 'Both generated_content and language are required fields.'}, status=400)

            response = bhashini_translate(generated_content, language)

            if response["status_code"] == 200:
                translated_content = response["translated_content"]
                return JsonResponse({
                    'generated_content': generated_content,
                    'translated_content': translated_content,
                    'selected_language': language
                }, status=200)
            else:
                return JsonResponse({'error': 'Translation failed.'}, status=500)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed.'}, status=405)


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
@api_view(['POST'])
@permission_classes([IsAuthenticated])
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

            # Assuming generate_bus_pro is a function that processes the proposal data
            proposal_content = generate_bus_pro(
                business_intro, proposal_objective, num_words, scope_of_work,
                project_phases, expected_outcomes, innovative_approaches,
                technologies_used, target_audience, budget_info, timeline,
                benefits, closing_remarks
            )

            # Encrypt the response content
            encrypted_content = encrypt_data({'generated_content': proposal_content})

            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed.'}, status=405)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def offer_letter_generator(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
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

            # Assuming generate_offer_letter is a function that processes the offer letter data
            offer_letter_content = generate_offer_letter(
                company_details, num_words, candidate_name, position_title, department, supervisor, status,
                location, start_date, compensation, benefits, work_hours, duration,
                terms, acceptance_deadline, contact_info, documents_needed, closing_remarks
            )

            # Encrypt the response content
            encrypted_content = encrypt_data({'generated_content': offer_letter_content})

            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed.'}, status=405)
 
@login_required
def generated_content(request):
    return render(request, 'generated_content.html')


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
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def summarize_document(request):
    try:
        # Extract and decrypt the incoming payload
        encrypted_content = request.POST.get('encrypted_content')
        if not encrypted_content:
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        decrypted_content = decrypt_data(encrypted_content)
        data = json.loads(decrypted_content)

        # Extract data from the request
        document_context = data.get('document_context')
        main_subject = data.get('main_subject')
        summary_purpose = data.get('summary_purpose')
        length_detail = data.get('length_detail')
        important_elements = data.get('important_elements')
        audience = data.get('audience')
        tone = data.get('tone')
        format = data.get('format')
        additional_instructions = data.get('additional_instructions')
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
            # Encrypt the response content
            encrypted_content = encrypt_data({'generated_content': summary_content})

            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        # Handle case where summary generation failed
        return JsonResponse({'error': 'Failed to generate summary. Please try again.'}, status=500)

    except Exception as e:
        # Handle any exceptions
        return JsonResponse({'error': str(e)}, status=500)

    # Handle GET request or any other method
    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def content_generator(request):
    try:
        # Extract and decrypt the incoming payload
        encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
        if not encrypted_content:
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        decrypted_content = decrypt_data(encrypted_content)
        data = json.loads(decrypted_content)

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
            # Encrypt the response content
            encrypted_response_content = encrypt_data({'generated_content': content})
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

        return JsonResponse({'error': 'Failed to generate content. Please try again.'}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def sales_script_generator(request):
    try:
        # Extract and decrypt the incoming payload
        encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
        if not encrypted_content:
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        decrypted_content = decrypt_data(encrypted_content)
        data = json.loads(decrypted_content)

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
            # Encrypt the response content
            encrypted_content = encrypt_data({'generated_content': sales_script})
            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        return JsonResponse({'error': 'Failed to generate sales script. Please try again.'}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    logout(request)
    return JsonResponse({'success': 'Logged out successfully'}, status=200)

