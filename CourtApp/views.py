from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
from django.core.paginator import Paginator
from django.contrib import messages
from django.core.mail import send_mail
import secrets
import string
from django.conf import settings
from UserApp.models import *
from UserApp.Algorithm import *
from UserApp.views import *
from django.http import JsonResponse
from cryptography.fernet import Fernet
from django.http import HttpResponse
from cryptography.hazmat.primitives import serialization
import os
# Create your views here.


def court_login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Default credentials
        default_username = 'court'
        default_password = 'court'
        email = 'court@gmail.com'

        # Check for default credentials
        if username == default_username and password == default_password:
            if not CourtUser.objects.filter(username=default_username, password=default_password).exists():
                savedata = CourtUser(username=default_username, password=default_password, email=email)
                savedata.save()
            request.session['username'] = username
            messages.success(request, "Login successful!")
            return redirect('court_dashboard')  # Redirect to a dashboard or another view

        # Check if credentials match any user in the courtUser model
        try:
            user = CourtUser.objects.get(username=username, password=password)
            request.session['username'] = username
            messages.success(request, "Login successful!")
            return redirect('court_dashboard')  # Redirect to a dashboard or another view
        except CourtUser.DoesNotExist:
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, 'court_login.html')


def court_dashboard(req):
    return render(req, 'court_dashboard.html')


def send_evidence_req(req):
    if req.method == "POST":
        case_number = req.POST.get('case_number')

        if case_number:
            # Update the status of the evidence to 'requested'
            evidence = EvidenceDetails.objects.filter(case_number=case_number).first()
            if evidence:
                evidence.status = 'courtrequest'
                evidence.save()
                msg = "Request sent successfully."
                return render(req,'send_evidence_req.html',{'msg':msg})
            else:
                messages.error(req, "No evidence found for the given case number.")
            return redirect('court_dashboard')
        else:
            messages.error(req, "Please enter a case number.")
            return redirect('court_dashboard')
    
    # Query the database for all evidence that hasn't been shared with the court
    # Exclude evidence that has already been requested or shared
    pending_evidence = EvidenceDetails.objects.exclude(
        status__in=['courtrequest', 'sharedkryscourt', 'decryptionshared']
    ).order_by('-id')
    
    print(f"Found {pending_evidence.count()} pending evidence files")  # Debug print
    
    context = {
        'pending_evidence': pending_evidence
    }
    
    return render(req, 'send_evidence_req.html', context)
        
def Court_Response(req):
    """
    View to display files that have been shared with the court and are ready for download.
    """
    try:
        username = req.session['username']
        
        # Get all files that have been shared with the court
        Data = EvidenceDetails.objects.filter(status__in=['sharedkryscourt', 'decryptionshared'])
        paginator = Paginator(Data, 5)  # Show 5 items per page
        page_number = req.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        context = {
            'page_obj': page_obj,
            'username': username
        }
        
        return render(req, 'Court_Response.html', context)
    except Exception as e:
        messages.error(req, f"Error loading shared files: {str(e)}")
        return redirect('court_dashboard')


def decrypt_court_file(req, id):
    """
    View to handle OTP verification and decryption of files in the court app.
    """
    try:
        if req.method == "POST":
            otp = req.POST.get('decryptiokey')
            if not otp:
                return JsonResponse({
                    'status': 'error',
                    'message': 'OTP is required.'
                }, status=400)

            try:
                evidence = EvidenceDetails.objects.get(id=id)
            except EvidenceDetails.DoesNotExist:
                return JsonResponse({
                    'status': 'error',
                    'message': 'File not found.'
                }, status=404)

            if not evidence.otp:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No OTP has been generated for this file.'
                }, status=400)

            if evidence.otp == otp:
                try:
                    # Get the file path
                    file_path = evidence.file_path.path
                    print(f"Original file path: {file_path}")  # Debug print
                    
                    # Read the encrypted file
                    with open(file_path, 'rb') as file:
                        encrypted_data = file.read()
                    
                    # Load the keys properly
                    private_key = serialization.load_pem_private_key(
                        evidence.private_key,
                        password=None
                    )
                    
                    public_key = serialization.load_pem_public_key(evidence.public_key)
                    
                    print("Keys loaded successfully")  # Debug print
                    
                    # Decrypt the file data
                    decrypted_data = decrypt_file_data(private_key, encrypted_data, public_key)
                    
                    # Create a temporary file for the decrypted data
                    temp_dir = os.path.join(settings.MEDIA_ROOT, 'static', 'DecryptedFiles')
                    os.makedirs(temp_dir, exist_ok=True)
                    
                    temp_filename = f"decrypted_{os.path.basename(evidence.filename)}"
                    temp_file_path = os.path.join(temp_dir, temp_filename)
                    
                    print(f"Saving decrypted file to: {temp_file_path}")  # Debug print
                    
                    with open(temp_file_path, 'wb') as file:
                        file.write(decrypted_data)
                    
                    # Update the file path to point to the decrypted file
                    evidence.file_path = os.path.join('static', 'DecryptedFiles', temp_filename)
                    evidence.status = 'decryptionshared'
                    evidence.save()
                    
                    return JsonResponse({
                        'status': 'success',
                        'message': 'OTP verified successfully. You can now download the file.',
                        'download_url': f'/downloadfile/{id}/'
                    })
                except Exception as e:
                    print(f"Error during decryption: {str(e)}")  # For debugging
                    return JsonResponse({
                        'status': 'error',
                        'message': f'Error during file decryption: {str(e)}'
                    }, status=500)
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid OTP. Please try again.'
                }, status=400)
                
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid request method.'
        }, status=405)
        
    except Exception as e:
        print(f"Error in decrypt_court_file: {str(e)}")  # For debugging
        return JsonResponse({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }, status=500)


def downloadfile(request, id):
    try:
        # Fetch the encrypted record from the database
        encrypted_record = EvidenceDetails.objects.get(id=id)
        
        if encrypted_record.status != 'decryptionshared':
            messages.error(request, "File is not ready for download. Please verify OTP first.")
            return redirect('Court_Response')

        # Get the decrypted file path
        file_path = encrypted_record.file_path.path
        
        # Read the decrypted file
        with open(file_path, 'rb') as file:
            decrypted_data = file.read()

        # Send the decrypted file as an HTTP response
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{encrypted_record.filename}"'
        return response

    except EvidenceDetails.DoesNotExist:
        messages.error(request, "File not found or already deleted.")
        return redirect('Court_Response')

    except Exception as e:
        print(f"Error in downloadfile: {str(e)}")  # For debugging
        messages.error(request, f"An error occurred during download: {str(e)}")
        return redirect('Court_Response')
