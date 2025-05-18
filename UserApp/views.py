from django.shortcuts import render
from django.shortcuts import render,redirect, get_object_or_404
from .models import *
from django.contrib import messages
from django.core.mail import send_mail
import secrets
import string
from django.conf import settings
from .Algorithm import *
from django.core.paginator import Paginator
from django.http import HttpResponse
import hashlib
import binascii
from .models import UserRegistration


#File handlers
import json
from django.core.files.base import ContentFile
import pandas as pd
from docx import Document
import PyPDF2
import pdfplumber

# Create your views here.

#Algorithm code


# Encrypt the data using AES in GCM mode for authenticated encryption
def encrypt_data(data, key):
    iv = os.urandom(12)  # Recommended size for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + encrypted_data

# Decrypt the data using AES in GCM mode
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[28:]) + decryptor.finalize()
    return decrypted_data

def index(req):
    return render(req, 'index.html')


# def user_Registration(req):
#     if req.method == "POST":
#         username = req.POST['username']
#         useremail = req.POST['useremail']
#         userphone = req.POST['userphone']
#         useraddress = req.POST['useraddress']
#         userpassword = req.POST['userpassword']
#         conformpassword = req.POST['confirmpassword']
#         if UserRegistration.objects.filter(email=useremail).exists():
#             msg = "This email address is already registered, try with another email"
#             return render(req, 'user_registration.html', {'msg': msg})
        
#         # Create and save the new user
#         user_data = UserRegistration(name=username, email=useremail,password=userpassword, phone=userphone, address=useraddress)
#         user_data.save()
                
#         email_subject = 'Login Credentials'
#         email_message = f'Hello {username},\n\nThank you for registering with us!\n\nHere are your registration details:\n\nuser Name: {username}\n\nPlease keep this information safe.\n\nBest regards,\nYour Website Team'
#         send_mail(email_subject, email_message, 'appcloud887@gmail.com', [useremail])
        
#         messages.success(req, "Registration successful! Please log in.")
#         return redirect('user_login')
    
#     return render(req, 'user_registration.html')




# def user_login(req):
#     if req.method == "POST":
#         useremail = req.POST['useremail']
#         userpassword = req.POST['userpassword']
        
#         if UserRegistration.objects.filter(email=useremail, status='active').exists():
#             user_data = UserRegistration.objects.get(email=useremail)
#             if user_data.password == userpassword:
#                 req.session['useremail'] = useremail
#                 req.session['username'] = user_data.name
#                 req.session['id'] = user_data.id

#                 return redirect('user_home')
#             else:
#                 error = "Password is incorrect, try again."
#                 return render(req, 'user_login.html', {'error': error})
#         else:
#             error = "Something went wrong, contact to admin otherwise, please register."
#             return render(req, 'user_login.html', {'error': error})
    
#     # Show registration success message if available
#     msg = "Registration successful! Please log in."
#     return render(req, 'user_login.html', {'msg': msg})



from django.shortcuts import render
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from .models import UserModel
from .sbvm import (
    generate_secret_key, create_block_data, sign_block, calculate_block_hash, encrypt_secret_key, generate_aes_key
)


def user_Registration(request):
    # UserModel.objects.all().delete()
    if request.method == "POST":
        # Retrieve the user data from the request
        username = request.POST['username']
        email = request.POST['useremail']
        phone = request.POST['userphone']
        address = request.POST['useraddress']
        password = request.POST['userpassword']
        confirm_password = request.POST['confirmpassword']
        
        
        # Validate passwords
        if password != confirm_password:
            return JsonResponse({'status': 'Passwords do not match!'}, status=400)

        # Hash password securely
        password_hash = make_password(password)

        # Generate secret key using EEO
        secret_key = generate_secret_key()

        # Generate AES key
        aes_key = generate_aes_key()

        # Encrypt the secret key using AES
        encrypted_secret_key = encrypt_secret_key(secret_key, aes_key)

        # Create authentication block
        block_data = create_block_data(username, email, phone, address, password_hash)

        # Compute block hash
        block_hash = calculate_block_hash(block_data)

        print(block_hash)

        # Sign the block
        signature = sign_block(block_hash, secret_key)

        # Save user to database
        user = UserModel.objects.create(
            username=username,
            email=email,
            phone=phone,
            address=address,
            password_hash=password_hash,
            secret_key=encrypted_secret_key,
            aes_key=aes_key,  # Save AES key for decryption
            block_hash=block_hash,
            signature=signature
        )
        user.save()
        return redirect('user_login')
        # return JsonResponse({'status': 'User registered successfully!'}, status=201)
    
    
    return render(request, 'user_registration.html')



from django.http import JsonResponse
from django.shortcuts import render
from .models import UserModel
from .sbvm import calculate_block_hash, verify_block, decrypt_secret_key, create_block_data
from django.contrib.auth.hashers import check_password
import random
def user_login(request):
    if request.method == "POST":
        email = request.POST['useremail']
        password = request.POST['userpassword']

        try:
            if UserModel.objects.filter(email=email, status= 'active').exists():

                user = UserModel.objects.get(email=email)
            else:
                msg = 'User Not Activated By Admin'
                return render(request, 'user_login.html',{'msg':msg})

        except UserModel.DoesNotExist:
            return JsonResponse({'status': 'User not found'}, status=404)

        # Decrypt secret key using AES
        secret_key = decrypt_secret_key(user.secret_key, user.aes_key)

        # Verify password
        if not check_password(password, user.password_hash):
            return JsonResponse({'status': 'Authentication failed'}, status=401)

        # # Verify authentication block
        # block_data = create_block_data(user.username, user.email, user.phone, user.address, user.password_hash)
        # block_hash = calculate_block_hash(block_data)

        if verify_block(user.block_hash, user.signature, secret_key):
            request.session['useremail'] = user.email
            request.session['username'] = user.username
            otp = random.randint(100000,999999)
            user.otp = otp
            email_subject = 'OTP Details'
            email_message = f'Hello {user.email},\n\nWelcome To Our Website!\n\nHere are your OTP details:\nEmail: {user.email}\nOTP: {user.otp}\n\nPlease keep this information safe.\n\nBest regards,\nYour Website Team'
            send_mail(email_subject, email_message, 'cse.takeoff@gmail.com', [user.email])
            user.save()

            return redirect('otp')
            
            # return JsonResponse({'status': 'Authentication successful'})
        else:
            return JsonResponse({'status': 'Authentication failed (invalid block signature)'}, status=401)

    return render(request, 'user_login.html')


def otp(request):
    if request.method == "POST":
        print('-----')
        email = request.session['useremail']
        otp1 = request.POST['otp1']
        otp2 = request.POST['otp2']
        otp3 = request.POST['otp3']
        otp4 = request.POST['otp4']
        otp5 = request.POST['otp5']
        otp6 = request.POST['otp6']
        otp = int(otp1+otp2+otp3+otp4+otp5+otp6)
        # otp = int(otp1+otp2+otp3+otp4)
        if UserModel.objects.filter(email=email, otp=otp).exists():
            return redirect('user_home')
        else:
            messages.success(request, 'Invalid Passsword!')
            return redirect('otp')
    return render(request, 'otp.html')



def user_home(req):
    if req.session.get('useremail'):
        useremail = req.session.get('useremail')
        username = req.session.get('username')
        id = req.session.get('id')
        return render(req, 'user_home.html',{'username':username})
    else:
        return redirect('user_login')


from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Encrypt the file data
def encrypt_file(public_key, file_data):
    # Generate a shared key using ECDH (Elliptic Curve Diffie-Hellman)
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key using PBKDF2HMAC
    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(shared_key)

    # Pad the file data to match AES block size (128 bits / 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Generate random Initialization Vector (IV) for CBC mode
    iv = os.urandom(16)

    # Encrypt the data using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenate salt, IV, and encrypted data for decryption
    return salt + iv + encrypted_data


import hashlib

def hash_string(input_string):
    # Ensure the input is in bytes, if it's a string
    if isinstance(input_string, str):
        input_string = input_string.encode()
    return hashlib.sha256(input_string).hexdigest()

import uuid

from django.conf import settings
def Upload_Files(req):
    useremail = req.session.get('useremail')
    username = req.session.get('username')
    
    if req.method == "POST":
        # Get form data
        file = req.FILES.get('file')
        case_number = req.POST.get('case_number')
        evidence_type = req.POST.get('evidence_type')
        evidence_description = req.POST.get('evidence_description')

        if not file:
            msg = "Please select a file to upload."
            return render(req, 'Upload_Files.html', {"msg": msg, 'username': username})

        # Create upload directory if it doesn't exist
        upload_folder = os.path.join(settings.MEDIA_ROOT, 'static', 'EnTextFiles')
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate unique filename
        unique_filename = f"{uuid.uuid4().hex}_{file.name}"
        file_path = os.path.join(upload_folder, unique_filename)
        
        try:
            # Read file data and calculate hash
            file_data = file.read()
            file_hash = hash_string(file_data)
            
            # Check for duplicate files
            if EvidenceDetails.objects.filter(file_hash=file_hash).exists():
                msg = f"{file.name} Data already existed."
                return render(req, 'Upload_Files.html', {"msg": msg, 'username': username})

            # Load the public key
            public_key = serialization.load_pem_public_key(public_pem)

            # Encrypt the file data
            encrypted_message = encrypt_file(public_key, file_data)

            # Save the encrypted file
            with open(file_path, 'wb') as f:
                f.write(encrypted_message)

            # Save evidence details with relative path
            relative_path = os.path.join('static', 'EnTextFiles', unique_filename)
            evidence = EvidenceDetails.objects.create(
                file_hash=file_hash,
                owneremail=useremail,
                ownername=username,
                encrypted_data=encrypted_message, 
                case_number=case_number,
                evidence_type=evidence_type,
                filename=file.name,
                evidence_description=evidence_description,
                file_path=relative_path,
                public_key=public_pem,
                private_key=private_pem,
                status='pending'  # Set initial status
            )
            
            print(f"File uploaded successfully: {evidence.id}")  # Debug print
            msg = f"{file.name} file uploaded and encrypted successfully."
            return render(req, 'Upload_Files.html', {"msg": msg, 'username': username})
            
        except Exception as e:
            print(f"Error during file upload: {str(e)}")  # Debug print
            msg = f"Error uploading file: {str(e)}"
            return render(req, 'Upload_Files.html', {"msg": msg, 'username': username})

    return render(req, 'Upload_Files.html', {'username': username})


def View_Encrypted(req):
    username = req.session.get('username')
    useremail = req.session.get('useremail')
    
    if not useremail:
        return redirect('user_login')
    
    try:
        # Get all files for the current user
        Data = EvidenceDetails.objects.filter(owneremail=useremail).order_by('-id')
        print(f"Found {Data.count()} files for user {useremail}")  # Debug print
        
        # Add pagination
        paginator = Paginator(Data, 5)  # Show 5 items per page
        page_number = req.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        context = {
            'page_obj': page_obj,
            'username': username,
            'total_files': Data.count()  # Add total count to context
        }
        return render(req, 'View_Encrypted.html', context)
    except Exception as e:
        print(f"Error in View_Encrypted: {str(e)}")  # Debug print
        messages.error(req, f"Error loading files: {str(e)}")
        return render(req, 'View_Encrypted.html', {'username': username})






from django.http import HttpResponse
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def decrypt_file_data(private_key, encrypted_data, public_key):
    try:
        # Extract the salt (16 bytes), IV (16 bytes), and encrypted message
        salt = encrypted_data[:16]  # First 16 bytes are the salt
        iv = encrypted_data[16:32]  # Next 16 bytes are the IV
        encrypted_message = encrypted_data[32:]  # The rest is the encrypted message

        # Generate a shared key using ECDH
        shared_key = private_key.exchange(ec.ECDH(), public_key)

        # Derive the symmetric key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(shared_key)

        # Decrypt the file data using AES in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data
    except Exception as e:
        print(f"Error in decryption: {str(e)}")  # For debugging
        raise Exception(f"Error in decryption: {str(e)}")





def download_decrypt_file(request, id):
    try:
        # Fetch the encrypted record from the database
        encrypted_record = EvidenceDetails.objects.get(id=id)

        # Decrypt the text file
        private_key = serialization.load_pem_private_key(
            encrypted_record.private_key,
            password=None
        )

        public_key_pem = encrypted_record.public_key
        public_key = serialization.load_pem_public_key(public_key_pem)

        encrypted_data = encrypted_record.encrypted_data  # Encrypted data saved in the DB

        # Decrypt the file data
        decrypted_data = decrypt_file_data(private_key, encrypted_data, public_key)

        # Send the decrypted text file as an HTTP response
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{encrypted_record.filename}"'
        return response

    except EvidenceDetails.DoesNotExist:
        # Handle file not found in the database
        messages.error(request, "File not found or already deleted.")
        return redirect('View_Encrypted')  # Changed from 'viewfiles' to 'View_Encrypted'

    except Exception as e:
        # Handle general errors during decryption
        messages.error(request, f"An error occurred during decryption: {str(e)}")
        return redirect('View_Encrypted')  # Changed from 'viewfiles' to 'View_Encrypted'



def view_encrypted_data(request, fileid):
    # Fetch the EvidenceDetails object with the given fileid
    data = get_object_or_404(EvidenceDetails, fileid=fileid)  # Use `id` to match the primary key field
    encrypted_content = data.evidence_file.read()  # Read the file content
    response = HttpResponse(encrypted_content, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{data.filename}"'
    return response  


def View_Response(req):
    username = req.session['username']
    useremail=req.session['useremail']
    # OwnerUploadData.objects.all().delete()
    Data =EvidenceDetails.objects.filter(owneremail=useremail, status='decryptionshared')
    paginator = Paginator(Data, 5)  # Show 10 items per page
    page_number = req.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    return render(req, 'View_Response.html', context)


def decrypt_file(req):
    username = req.session['username']
    useremail = req.session['useremail']

    if req.method == "POST":
        decryptiokey = req.POST.get('decryptiokey')
        
        # Fetch the encrypted data using the decryption key as a string
        Data = EvidenceDetails.objects.get(encryption_key=decryptiokey)  # Use the salt stored as hex string

        # Generate the decryption key using the salt
        salt = bytes.fromhex(decryptiokey)
        encryption_key = generate_key(password="StrongPassword", salt=salt)  # Replace "StrongPassword" with a secure password management mechanism

        # Read the encrypted content from the file
        encrypted_content = Data.evidence_file.read()

        # Decrypt the content using the stored encryption key
        decrypted_content = decrypt_data(encrypted_content, encryption_key)

        # Prepare the response to download the decrypted file
        response = HttpResponse(decrypted_content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{Data.filename}"'

        # Update the status in the database
        Data.status = 'decrypted'
        Data.save()

        return response

    return render(req, 'Decrypt_File.html', {'username': username})


def Court_Request(req):
    username = req.session['username']
    useremail=req.session['useremail']
    # OwnerUploadData.objects.all().delete()
    Data =EvidenceDetails.objects.filter(owneremail=useremail, status='courtrequest')
    paginator = Paginator(Data, 5)  # Show 10 items per page
    page_number = req.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }   
    return render(req, 'Court_Request.html', context)


def Share_Keys(request, id):
    """
    View to handle sharing encryption keys with the court using OTP verification.
    """
    try:
        # Get the evidence file
        evidence = EvidenceDetails.objects.get(id=id)
        
        if request.method == "POST":
            # Generate a 6-digit OTP
            otp = ''.join(secrets.choice(string.digits) for _ in range(6))
            
            # Store the OTP in the evidence record
            evidence.otp = otp
            evidence.status = 'sharedkryscourt'  # Update status to indicate file is shared with court
            evidence.save()
            
            # Send OTP via email
            subject = 'OTP for Evidence Access'
            message = f'Your OTP for accessing evidence file "{evidence.filename}" is: {otp}\n\nPlease use this OTP in the Court App to access the file.'
            from_email = 'cse.takeoff@gmail.com'  # Use the same email as in user_login
            recipient_list = ['haran.ritvick@gmail.com','maneeshababburi07@gmail.com']  # Court's email address
            
            try:
                send_mail(subject, message, from_email, recipient_list)
                print(f"OTP sent successfully: {otp}")  # For debugging
            except Exception as e:
                print(f"Error sending email: {str(e)}")  # For debugging
                # Continue even if email fails, as the OTP is stored in the database
            
            # Return JSON response for AJAX handling
            return JsonResponse({
                'status': 'success',
                'message': 'Keys have been shared with the court successfully. The file will be visible in the Court App.'
            })
            
        return render(request, 'share_keys.html', {'evidence': evidence})
        
    except EvidenceDetails.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Evidence file not found.'
        }, status=404)
    except Exception as e:
        print(f"Error in Share_Keys: {str(e)}")  # For debugging
        return JsonResponse({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }, status=500)
