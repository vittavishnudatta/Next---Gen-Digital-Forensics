from django.shortcuts import render,redirect
from django.contrib import messages
from .models import *
from UserApp.models import *
from django.core.paginator import Paginator
from django.contrib import messages
from django.core.mail import send_mail
import secrets
import string
from django.conf import settings
from CourtApp.models import *

# Create your views here.


def admin_login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Default credentials
        default_username = 'admin'
        default_password = 'admin'
        email = 'admin@gmail.com'

        # Check for default credentials
        if username == default_username and password == default_password:
            # Check if the default admin user is already saved
            if not AdminUser.objects.filter(username=default_username, password=default_password).exists():
                savedata = AdminUser(username=default_username, password=default_password, email=email)
                # savedata.save()
            
            # Set session and redirect to dashboard
            request.session['username'] = username
            messages.success(request, "Login successful!")
            return redirect('admin_dashboard')  # Redirect to a dashboard or another view

        # Check if credentials match any user in the AdminUser model
        try:
            user = AdminUser.objects.get(username=username, password=password)
            request.session['username'] = username
            messages.success(request, "Login successful!")
            return redirect('admin_dashboard')  # Redirect to a dashboard or another view
        except AdminUser.DoesNotExist:
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, 'admin_login.html')



def admin_dashboard(req):
    # Check if user is logged in
    return render(req, 'admin_dashboard.html')

def View_Request(req):
    # OwnerUploadData.objects.all().delete()
    Data =UserModel.objects.filter(status='pending')
    paginator = Paginator(Data, 5)  # Show 10 items per page
    page_number = req.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    return render(req, 'authenticate_users.html', context)


def acceptrequest(request, email):
    update = UserModel.objects.get(email=email)
    update.status = "active"
    email = update.email
    update.save()
    message = f'Hi {email},\n\n Your Registration Request Has Been Accepted By The Admin. Now you can login. \n\nThis message is automatically generated, so please do not reply to this email.\n\nThank you.\n\nRegards,\nAdmin'
    subject = "CLOUD ASSISTED PRIVACY PRESERVING FILE ACCEPTANCE FROM ADMIN"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list, fail_silently=False)

    return redirect('View_Request')


def rejectrequest(request,email):
    update = UserModel.objects.get(email=email)
    update.status = "rejected"
    email = update.email
    update.save()
    message = f'Hi {email},\n\n Your Registration Request Has Been Rejected By The Admin. You cant login, contact to admin. \n\nThis message is automatically generated, so please do not reply to this email.\n\nThank you.\n\nRegards,\nAdmin'
    subject = "CLOUD ASSISTED PRIVACY PRESERVING FILE REJECTED FROM ADMIN"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list, fail_silently=False)
    # fail= "Sent The Rejected Status To The User"
    return redirect('View_Request')


def Active_Users(req):
    # Check if admin is logged in
    if 'username' not in req.session:
        messages.error(req, "Please login as admin to view users.")
        return redirect('admin_login')
        
    Data = UserModel.objects.filter(status='active')
    paginator = Paginator(Data, 5)  # Show 10 items per page
    page_number = req.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    return render(req, 'Active_Users.html', context)


def Requested_Users(req):
    # OwnerUploadData.objects.all().delete()
    Data =EvidenceDetails.objects.filter(status='requested')
    paginator = Paginator(Data, 5)  # Show 10 items per page
    page_number = req.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    return render(req, 'Requested_Users.html', context)


def send_keys(request, owneremail):
    # Retrieve all records with the matching owneremail
    uploads = EvidenceDetails.objects.filter(owneremail=owneremail)
    
    if uploads.exists():
        for update in uploads:
            update.status = "decryptionshared"
            update.save()

            email = update.owneremail
            message = (
                f'Hi {email},\n\n'
                f'Your file request has been accepted by the admin. Here is your decryption key: {update.encryption_key}. '
                f'Now you can log in.\n\n'
                f'This message is automatically generated, so please do not reply to this email.\n\n'
                f'Thank you.\n\n'
                f'Regards,\nAdmin'
            )
            subject = "Decryption Key Has Been Shared"
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [email]
            send_mail(subject, message, email_from, recipient_list, fail_silently=False)

        msg = "Decryption key shared with the requested user(s) successfully."
    else:
        msg = "No records found for the provided email."

    return render(request, 'Requested_Users.html', {'msg': msg})


def forgotpass(request):
    return render(request, 'forgotpass.html')

def reset_pass(request):
    if request.method == "POST":
        email = request.POST.get('Email')
        cloud_user = AdminUser.objects.filter(email=email).first()
        kgc_user = CourtUser.objects.filter(email=email).first()
        user = cloud_user or kgc_user
        if user:
            email_subject = 'Password Reset'
            url = 'http://127.0.0.1:8000/password_reset/'
            email_message = f'Hello {user},\n\nThank you for contacting to us for password reset!\n\nHere are your details:\n\nUsername: {user}\nEmail: {email}\n Reset Your Password Here: {url}\n\nPlease keep this information safe.\n\nBest regards,\nYour Website Team'
            send_mail(email_subject, email_message, 'appcloud887@gmail.com', [email])
            messages.success(request, 'Reset Password Link has been sent to your registered Email ID')
            return redirect('password_reset')
        else:
            messages.success(request, 'User was not Found')
            return redirect('forgotpass')

def password_reset(request):
    return render(request, 'reset-pass.html')


def update_pass(request):
    if request.method == 'POST':
        email = request.POST.get('Email')
        new_pwd = request.POST.get('password')
        confirm_pwd = request.POST.get('confirm_password')
        if new_pwd == confirm_pwd:
            cloud_user = AdminUser.objects.filter(email=email).first()
            kgc_user = CourtUser.objects.filter(email=email).first()
            user = cloud_user or kgc_user
            if user:
                user.password=new_pwd
                user.save()
                messages.success(request, 'Your password was successfully updated')
                if isinstance(user, AdminUser):
                    return redirect('admin_login')
                else:
                    return redirect('court_login')
            else:
                messages.success(request, 'User was not Found')
                return redirect('password_reset')
        else:
            messages.success(request, 'Password and Confirm Password do not match')
            return redirect('password_reset')

def delete_user(request, email):
    # Check if admin is logged in
    if 'username' not in request.session:
        messages.error(request, "Please login as admin to delete users.")
        return redirect('admin_login')
        
    try:
        user = UserModel.objects.get(email=email)
        user.delete()
        messages.success(request, f"User {email} has been deleted successfully.")
    except UserModel.DoesNotExist:
        messages.error(request, f"User {email} not found.")
    return redirect('Active_Users')