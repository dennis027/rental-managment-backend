from django.shortcuts import render, get_object_or_404
from rest_framework import generics, status,filters
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.core.exceptions import ValidationError
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.db import IntegrityError, transaction
from django.core.mail.message import BadHeaderError
from django.utils import timezone
from datetime import timedelta
import random
import logging
from datetime import datetime
from rest_framework.permissions import IsAuthenticated 
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.core.cache import cache
from .models import Customer, Expense, MaintenanceRequest, Payment, Property, Receipt, RentalContract, SystemParameter, Unit
from .serializers import CustomerSerializer, ExpenseSerializer, MaintenanceRequestSerializer, PaymentSerializer, PropertySerializer, ReceiptSerializer, RentalContractSerializer, SystemParameterSerializer, UnitSerializer
from rest_framework import viewsets
from django.utils.timezone import now
from django.db.models import Count, Sum, Avg,Q



from .serializers import (
    PasswordResetCodeCheckSerializer, 
    RegisterSerializer, 
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    ResendActivationSerializer
)
from .utils import generate_activation_link, generate_password_reset_link
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "success": False,
                    "error": "validation_error",
                    "message": "Invalid input data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            with transaction.atomic():
                user = serializer.save()
                
                try:
                    activation_link = generate_activation_link(user, request)
                    
                    # Render HTML email template
                    html_content = render_to_string('emails/activation_email.html', {
                        'user': user,
                        'activation_link': activation_link,
                        'site_name': 'RentSystem',
                    })
                    
                    # Create plain text version
                    text_content = strip_tags(html_content)
                    
                    # Alternative plain text message
                    plain_text_message = f"""
                    Hi {user.username},

                    Welcome to RentSystem! 

                    Please click the link below to activate your account:
                    {activation_link}

                    This activation link will expire in 24 hours for security reasons.

                    If you didn't create this account, please ignore this email.

                    Best regards,
                    RentSystem Team

                    ---
                    This is an automated email, please do not reply directly to this message.
                    """.strip()
                    
                    subject = "Activate your RentSystem Account"
                    
                    # Create email with both HTML and plain text versions
                    email = EmailMultiAlternatives(
                        subject=subject,
                        body=plain_text_message,  # Plain text version
                        from_email=None,  # uses DEFAULT_FROM_EMAIL
                        to=[user.email],
                    )
                    email.attach_alternative(html_content, "text/html")
                    email.send(fail_silently=False)
                    
                    logger.info(f"Registration successful for user: {user.email}")
                    
                    return Response({
                        "success": True,
                        "message": "Account created successfully. Please check your email to activate your account.",
                        "data": {
                            "user_id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_active": user.is_active
                        }
                    }, status=status.HTTP_201_CREATED)
                    
                except BadHeaderError:
                    logger.error(f"Bad email header when registering user: {user.email}")
                    return Response({
                        "success": False,
                        "error": "email_error",
                        "message": "Invalid email configuration. Please contact support."
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                except Exception as email_error:
                    logger.error(f"Email sending failed for user {user.email}: {str(email_error)}")
                    return Response({
                        "success": True,
                        "message": "Account created but activation email failed to send. Please contact support.",
                        "warning": "email_send_failed",
                        "data": {
                            "user_id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_active": user.is_active
                        }
                    }, status=status.HTTP_201_CREATED)

        except IntegrityError as e:
            logger.error(f"Database integrity error during registration: {str(e)}")
            if "email" in str(e).lower():
                return Response({
                    "success": False,
                    "error": "duplicate_email",
                    "message": "An account with this email already exists."
                }, status=status.HTTP_400_BAD_REQUEST)
            elif "username" in str(e).lower():
                return Response({
                    "success": False,
                    "error": "duplicate_username", 
                    "message": "This username is already taken."
                }, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    "success": False,
                    "error": "database_error",
                    "message": "Unable to create account due to data conflict."
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Unexpected error during registration: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error",
                "message": "An unexpected error occurred. Please try again later."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResendActivationWithRateLimitView(APIView):
    """
    Resend activation email with rate limiting to prevent abuse.
    Limits: 3 requests per hour per email address.
    """
    
    def post(self, request, *args, **kwargs):
        serializer = ResendActivationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "error": "validation_error",
                "message": "Invalid input data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        
        # Rate limiting check
        cache_key = f"resend_activation_{email.replace('@', '_at_').replace('.', '_dot_')}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 3:
            return Response({
                "success": False,
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Please wait an hour before requesting another activation email."
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        try:
            user = User.objects.get(email=email)
            
            if user.is_active:
                return Response({
                    "success": False,
                    "error": "already_activated",
                    "message": "This account is already activated."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                # Generate new activation link
                activation_link = generate_activation_link(user, request)
                
                # Render HTML email template
                html_content = render_to_string('emails/activation_email.html', {
                    'user': user,
                    'activation_link': activation_link,
                    'site_name': 'RentSystem',
                    'is_resend': True,
                })
                
                # Plain text version
                plain_text_message = f"""
                    Hi {user.username},

                    We received a request to resend your account activation email for RentSystem.

                    Please click the link below to activate your account:
                    {activation_link}

                    This activation link will expire in 24 hours for security reasons.

                    If you didn't request this email, please ignore this message.

                    Best regards,
                    RentSystem Team

                    ---
                    This is an automated email, please do not reply directly to this message.
                """.strip()
                
                subject = "RentSystem - Account Activation (Resend)"
                
                # Send email
                email_msg = EmailMultiAlternatives(
                    subject=subject,
                    body=plain_text_message,
                    from_email=None,
                    to=[user.email],
                )
                email_msg.attach_alternative(html_content, "text/html")
                email_msg.send(fail_silently=False)
                
                # Update rate limiting counter
                cache.set(cache_key, attempts + 1, timeout=3600)  # 1 hour timeout
                
                logger.info(f"Activation email resent successfully for user: {user.email} (attempt {attempts + 1})")
                
                return Response({
                    "success": True,
                    "message": "Activation email has been resent successfully. Please check your email.",
                    "data": {
                        "email": user.email,
                        "username": user.username,
                        "remaining_attempts": 2 - attempts
                    }
                }, status=status.HTTP_200_OK)
                
            except BadHeaderError:
                logger.error(f"Bad email header when resending activation for user: {user.email}")
                return Response({
                    "success": False,
                    "error": "email_error",
                    "message": "Invalid email configuration. Please contact support."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            except Exception as email_error:
                logger.error(f"Email sending failed when resending activation for user {user.email}: {str(email_error)}")
                return Response({
                    "success": False,
                    "error": "email_send_failed",
                    "message": "Failed to send activation email. Please try again later or contact support."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except User.DoesNotExist:
            return Response({
                "success": False,
                "error": "user_not_found",
                "message": "No account found with this email address."
            }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            logger.error(f"Unexpected error during activation email resend: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error",
                "message": "An unexpected error occurred. Please try again later."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            print (request.data)
            
            if not serializer.is_valid():
                return Response({
                    "success": False,
                    "error": "validation_error",
                    "message": "Invalid input data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            user = serializer.validated_data["user"]
            
            if not user.is_active:
                return Response({
                    "success": False,
                    "error": "account_inactive",
                    "message": "Account is not activated. Please check your email for activation link."
                }, status=status.HTTP_403_FORBIDDEN)

            try:
                refresh = RefreshToken.for_user(user)
                
                logger.info(f"Successful login for user: {user.email}")
                
                return Response({
                    "success": True,
                    "message": "Login successful",
                    "data": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_active": user.is_active
                        }
                    }
                }, status=status.HTTP_200_OK)
                
            except Exception as token_error:
                logger.error(f"Token generation failed for user {user.email}: {str(token_error)}")
                return Response({
                    "success": False,
                    "error": "token_error",
                    "message": "Unable to generate authentication tokens. Please try again."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error", 
                "message": "An unexpected error occurred during login."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ActivateAccountView(APIView):
    def get(self, request, uidb64, token):
        try:
            # Decode user ID
            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = get_object_or_404(User, pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({
                    "success": False,
                    "error": "invalid_link",
                    "message": "Invalid activation link."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if user is already active
            if user.is_active:
                return Response({
                    "success": True,
                    "message": "Account is already activated.",
                    "data": {"user_id": user.id}
                }, status=status.HTTP_200_OK)

            # Validate token
            if default_token_generator.check_token(user, token):
                try:
                    user.is_active = True
                    user.save()
                    
                    logger.info(f"Account activated for user: {user.email}")
                    
                    return Response({
                        "success": True,
                        "message": "Account activated successfully",
                        "data": {
                            "user_id": user.id,
                            "email": user.email,
                            "is_active": user.is_active
                        }
                    }, status=status.HTTP_200_OK)
                    
                except Exception as save_error:
                    logger.error(f"Failed to save user activation for {user.email}: {str(save_error)}")
                    return Response({
                        "success": False,
                        "error": "database_error",
                        "message": "Unable to activate account. Please try again."
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({
                    "success": False,
                    "error": "invalid_token",
                    "message": "Invalid or expired activation token."
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Unexpected error during account activation: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error",
                "message": "An unexpected error occurred during activation."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if not serializer.is_valid():
                return Response({
                    "success": False,
                    "error": "validation_error",
                    "message": "Invalid input data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            email = serializer.validated_data["email"]

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                # Return success to prevent email enumeration
                return Response({
                    "success": True,
                    "message": "If an account with this email exists, a password reset code has been sent."
                }, status=status.HTTP_200_OK)

            if not user.is_active:
                return Response({
                    "success": False,
                    "error": "account_inactive",
                    "message": "Account is not activated. Please activate your account first."
                }, status=status.HTTP_403_FORBIDDEN)

            try:
                with transaction.atomic():
                    # Generate 6-digit code
                    reset_code = str(random.randint(100000, 999999))
                    
                    # Save reset code + expiry (15 mins)
                    user.reset_code = reset_code
                    user.reset_code_expiry = timezone.now() + timedelta(minutes=15)
                    user.save()

                    # Send reset code by email
                    send_mail(
                        "Password Reset Code",
                        f"Hi {user.username},\n\nYour password reset code is: {reset_code}\n\nThis code will expire in 15 minutes.",
                        None,
                        [user.email],
                        fail_silently=False,
                    )
                    
                    logger.info(f"Password reset code sent to: {user.email}")

                    return Response({
                        "success": True,
                        "message": "Password reset code sent to email.",
                        "data": {"expires_in_minutes": 15}
                    }, status=status.HTTP_200_OK)
                    
            except BadHeaderError:
                logger.error(f"Bad email header for password reset: {user.email}")
                return Response({
                    "success": False,
                    "error": "email_error",
                    "message": "Invalid email configuration. Please contact support."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            except Exception as email_error:
                logger.error(f"Email sending failed for password reset {user.email}: {str(email_error)}")
                return Response({
                    "success": False,
                    "error": "email_send_failed",
                    "message": "Unable to send reset code. Please try again later."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Unexpected error during password reset request: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error",
                "message": "An unexpected error occurred. Please try again later."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetCodeCheckView(generics.GenericAPIView):
    serializer_class = PasswordResetCodeCheckSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if not serializer.is_valid():
                return Response({
                    "success": False,
                    "error": "validation_error",
                    "message": "Invalid input data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            email = serializer.validated_data["email"]
            reset_code = serializer.validated_data["reset_code"]

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({
                    "success": False,
                    "valid": False,
                    "error": "invalid_email",
                    "message": "Invalid email address."
                }, status=status.HTTP_400_BAD_REQUEST)

            if not user.reset_code or not user.reset_code_expiry:
                return Response({
                    "success": False,
                    "valid": False,
                    "error": "no_reset_request",
                    "message": "No password reset request found for this email."
                }, status=status.HTTP_400_BAD_REQUEST)

            if user.reset_code != reset_code:
                return Response({
                    "success": False,
                    "valid": False,
                    "error": "invalid_code",
                    "message": "Invalid reset code."
                }, status=status.HTTP_400_BAD_REQUEST)

            if user.reset_code_expiry < timezone.now():
                # Clean expired code
                user.reset_code = None
                user.reset_code_expiry = None
                user.save()
                
                return Response({
                    "success": False,
                    "valid": False,
                    "error": "code_expired",
                    "message": "Reset code has expired. Please request a new one."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Calculate remaining time
            remaining_seconds = int((user.reset_code_expiry - timezone.now()).total_seconds())
            
            return Response({
                "success": True,
                "valid": True,
                "message": "Reset code is valid.",
                "data": {
                    "expires_in_seconds": remaining_seconds,
                    "expires_in_minutes": round(remaining_seconds / 60, 1)
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Unexpected error during code validation: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error",
                "message": "An unexpected error occurred during validation."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if not serializer.is_valid():
                return Response({
                    "success": False,
                    "error": "validation_error",
                    "message": "Invalid input data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            email = serializer.validated_data["email"]
            reset_code = serializer.validated_data["reset_code"]
            new_password = serializer.validated_data["new_password"]

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({
                    "success": False,
                    "error": "invalid_email",
                    "message": "Invalid email address."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate reset code and expiry
            if not user.reset_code or not user.reset_code_expiry:
                return Response({
                    "success": False,
                    "error": "no_reset_request",
                    "message": "No password reset request found."
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if user.reset_code != reset_code:
                return Response({
                    "success": False,
                    "error": "invalid_code",
                    "message": "Invalid reset code."
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if user.reset_code_expiry < timezone.now():
                # Clean expired code
                user.reset_code = None
                user.reset_code_expiry = None
                user.save()
                
                return Response({
                    "success": False,
                    "error": "code_expired",
                    "message": "Reset code has expired. Please request a new one."
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                with transaction.atomic():
                    # Reset password
                    user.set_password(new_password)
                    user.reset_code = None
                    user.reset_code_expiry = None
                    user.save()
                    
                    logger.info(f"Password reset successfully for user: {user.email}")

                    return Response({
                        "success": True,
                        "message": "Password has been reset successfully.",
                        "data": {
                            "user_id": user.id,
                            "email": user.email
                        }
                    }, status=status.HTTP_200_OK)
                    
            except ValidationError as ve:
                return Response({
                    "success": False,
                    "error": "password_validation_error",
                    "message": "Password does not meet requirements.",
                    "details": ve.messages if hasattr(ve, 'messages') else [str(ve)]
                }, status=status.HTTP_400_BAD_REQUEST)
                
            except Exception as save_error:
                logger.error(f"Failed to save password reset for {user.email}: {str(save_error)}")
                return Response({
                    "success": False,
                    "error": "database_error",
                    "message": "Unable to reset password. Please try again."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Unexpected error during password reset: {str(e)}")
            return Response({
                "success": False,
                "error": "server_error",
                "message": "An unexpected error occurred during password reset."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response({
                    "success": False,
                    "error": "missing_token",
                    "message": "Refresh token is required for logout."
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                print("Logout error:", str(e))  # 👈 log to console
                return Response({
                    "success": False,
                    "error": "invalid_token",
                    "message": "Token is invalid or already blacklisted."
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                "success": True,
                "message": "Logout successful."
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("Unexpected logout error:", str(e))  # 👈 log to console
            return Response({
                "success": False,
                "error": "server_error",
                "message": f"Unexpected error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# property and unit views would go here, but are omitted for brevity.



# ----------------- Property APIs -----------------
class PropertyListCreate(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        properties = Property.objects.all().order_by("-created_at")
        serializer = PropertySerializer(properties, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PropertyDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        property_obj = get_object_or_404(Property, pk=pk)
        serializer = PropertySerializer(property_obj)
        return Response(serializer.data)

    def put(self, request, pk):
        """Full update (all fields required)"""
        property_obj = get_object_or_404(Property, pk=pk)
        serializer = PropertySerializer(property_obj, data=request.data)  # full update
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """Partial update (only provided fields will be updated)"""
        property_obj = get_object_or_404(Property, pk=pk)
        serializer = PropertySerializer(property_obj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        property_obj = get_object_or_404(Property, pk=pk)

        # Use the correct related_name
        if property_obj.units.exists():  # if related_name="units"
            property_obj.is_active = False
            property_obj.save()
            return Response(
                {"detail": "Property has related units, so it was disabled instead of deleted."},
                status=status.HTTP_200_OK
            )
        else:
            property_obj.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)


# ----------------- Unit APIs -----------------
class UnitListCreate(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        units = Unit.objects.select_related("property").all().order_by("-created_at")
        serializer = UnitSerializer(units, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UnitSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
            


class UnitDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        unit = get_object_or_404(Unit, pk=pk)
        serializer = UnitSerializer(unit)
        return Response(serializer.data)

    def put(self, request, pk):
        """Full update (all fields required)"""
        unit = get_object_or_404(Unit, pk=pk)
        serializer = UnitSerializer(unit, data=request.data)  # full update
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """Partial update (only provided fields will be updated)"""
        unit = get_object_or_404(Unit, pk=pk)
        serializer = UnitSerializer(unit, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        unit = get_object_or_404(Unit, pk=pk)
        unit.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    


# ----------------- Customer APIs -----------------
class CustomerListCreate(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        customers = Customer.objects.select_related("unit").all().order_by("-created_at")
        serializer = CustomerSerializer(customers, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CustomerSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomerDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        customer = get_object_or_404(Customer, pk=pk)
        serializer = CustomerSerializer(customer)
        return Response(serializer.data)

    def put(self, request, pk):  # full update
        customer = get_object_or_404(Customer, pk=pk)
        serializer = CustomerSerializer(customer, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):  # partial update
        customer = get_object_or_404(Customer, pk=pk)
        serializer = CustomerSerializer(customer, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        customer = get_object_or_404(Customer, pk=pk)
        # Soft delete instead of hard delete
        customer.is_active = False
        customer.save()
        return Response({"detail": "Customer disabled instead of deleted."}, status=status.HTTP_200_OK)


# ----------------- RentalContract APIs -----------------
class RentalContractListCreate(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        contracts = RentalContract.objects.select_related("customer", "unit").all().order_by("-created_at")
        serializer = RentalContractSerializer(contracts, many=True)
        return Response(serializer.data)

    @transaction.atomic
    def post(self, request):
        serializer = RentalContractSerializer(data=request.data)
        if serializer.is_valid():
            unit = serializer.validated_data["unit"]

            # 1️⃣ Prevent multiple active contracts per unit
            active_contract = RentalContract.objects.filter(unit=unit, is_active=True).first()
            if active_contract:
                return Response(
                    {"error": "This unit already has an active contract."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 2️⃣ Create the contract
            contract = serializer.save(is_active=True)

            # 3️⃣ Mark unit as occupied
            unit.status = "occupied"
            unit.save()

            # 4️⃣ Fetch system parameters (if exist)
            try:
                system_params = SystemParameter.objects.get(property=unit.property)
            except SystemParameter.DoesNotExist:
                system_params = None

            # 5️⃣ Auto-generate initial receipt
            self._create_initial_receipt(contract, request.user, system_params)

            return Response(RentalContractSerializer(contract).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _create_initial_receipt(self, contract, user, system_params=None):
        """
        Generate a receipt when a new rental contract is created.
        """
        # Determine deposit requirements
        water_deposit = 0
        electricity_deposit = 0
        service_charge = 0

        if system_params:
            if system_params.require_water_deposit:
                water_deposit = system_params.water_unit_cost or 0

            if system_params.require_electricity_deposit:
                electricity_deposit = system_params.electicity_unit_cost or 0

            if system_params.has_service_charge:
                service_charge = system_params.default_service_charge or 0

        # Create receipt
        Receipt.objects.create(
            contract=contract,
            issued_by=user,
            monthly_rent=contract.rent_amount,
            rental_deposit=contract.deposit_amount,
            electricity_deposit=electricity_deposit,
            water_deposit=water_deposit,
            service_charge=service_charge,
            previous_balance=0.00,
            other_charges=0.00
        )



class RentalContractCancel(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        contract = get_object_or_404(RentalContract, pk=pk)

        if not contract.is_active:
            return Response({"error": "Contract is already inactive."}, status=status.HTTP_400_BAD_REQUEST)

        # Cancel contract
        contract.is_active = False
        contract.end_date = timezone.now().date()
        contract.save()

        # Free up the unit
        unit = contract.unit
        unit.status = "vacant"
        unit = self.unit
        unit.balance = 0
        unit.save(update_fields=["balance"])
        unit.save()

        return Response({"message": f"Contract {contract.contract_number} has been cancelled."})


class RentalContractDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        contract = get_object_or_404(RentalContract, pk=pk)
        serializer = RentalContractSerializer(contract)
        return Response(serializer.data)

    def put(self, request, pk):
        contract = get_object_or_404(RentalContract, pk=pk)
        serializer = RentalContractSerializer(contract, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        return Response({"error": "Contracts cannot be deleted. Use cancel endpoint instead."},
                        status=status.HTTP_405_METHOD_NOT_ALLOWED)
    



class ContractSearchView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = RentalContract.objects.all().select_related("customer", "unit")
    serializer_class = RentalContractSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = [
        "contract_number",
        "customer__first_name",
        "customer__last_name",
        "customer__phone_number",
        "customer__email",
        "unit__unit_number"
    ]
    

# ----------------- Models (for payments) -----------------


class PaymentListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Payment.objects.all().order_by("-payment_date")
    serializer_class = PaymentSerializer


class PaymentDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer


# ----------------- Models (for expenses) -----------------

class ExpenseListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Expense.objects.all().order_by("-expense_date")
    serializer_class = ExpenseSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["property__name", "description", "recorded_by__username"]

    def perform_create(self, serializer):
        serializer.save(recorded_by=self.request.user)


class ExpenseDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated] 
    queryset = Expense.objects.all()
    serializer_class = ExpenseSerializer


#  ....................maintannance request .......................

class MaintenanceRequestListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MaintenanceRequest.objects.all().order_by("-reported_date")
    serializer_class = MaintenanceRequestSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["description", "status", "unit__name", "customer__name"]

    def perform_create(self, serializer):
        # Auto-attach the customer if logged in as customer
        if self.request.user.is_authenticated and hasattr(self.request.user, "customer"):
            serializer.save(customer=self.request.user.customer)
        else:
            serializer.save()


class MaintenanceRequestDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MaintenanceRequest.objects.all()
    serializer_class = MaintenanceRequestSerializer

    def perform_update(self, serializer):
        # If status changes to resolved → set resolved_date
        old_status = self.get_object().status
        new_status = self.request.data.get("status")
        if old_status != "resolved" and new_status == "resolved":
            serializer.save(resolved_date=now())
        else:
            serializer.save()






# #########################   ANALYTICS VIEWS  #########################

class PropertyUnitsAnalyticsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        properties = Property.objects.annotate(
            total_units=Count("units"),
            occupied_units=Count("units", filter=Q(units__status="occupied")),
            vacant_units=Count("units", filter=Q(units__status="vacant"))
        )

        results = []
        overall_total_units = 0
        overall_occupied = 0
        overall_vacant = 0

        for p in properties:
            overall_total_units += p.total_units
            overall_occupied += p.occupied_units
            overall_vacant += p.vacant_units

            percent_occupied = (p.occupied_units / p.total_units * 100) if p.total_units > 0 else 0
            percent_vacant = (p.vacant_units / p.total_units * 100) if p.total_units > 0 else 0

            results.append({
                "id": p.id,
                "name": p.name,
                "total_units": p.total_units,
                "occupied_units": p.occupied_units,
                "vacant_units": p.vacant_units,
                "percent_occupied": round(percent_occupied, 2),
                "percent_vacant": round(percent_vacant, 2)
            })

        overall_percent_occupied = (overall_occupied / overall_total_units * 100) if overall_total_units > 0 else 0
        overall_percent_vacant = (overall_vacant / overall_total_units * 100) if overall_total_units > 0 else 0

        return Response({
            "total_properties": len(results),
            "overall": {
                "total_units": overall_total_units,
                "occupied_units": overall_occupied,
                "vacant_units": overall_vacant,
                "percent_occupied": round(overall_percent_occupied, 2),
                "percent_vacant": round(overall_percent_vacant, 2)
            },
            "properties": results
        })
    

# ######## RECEIPT VIEW #########
class ReceiptListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Receipt.objects.all().select_related("contract", "issued_by")
    serializer_class = ReceiptSerializer


class ReceiptDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Receipt.objects.all().select_related("contract", "issued_by", "contract__unit__property", "contract__customer")
    serializer_class = ReceiptSerializer


class GenerateMonthlyReceiptsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        month = request.data.get("month")
        property_id = request.data.get("property_id")
        
        if not month:
            return Response(
                {"error": "❌ 'month' is required (e.g. 2025-11)."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not property_id:
            return Response(
                {"error": "❌ 'property_id' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        try:
            year, month_num = map(int, month.split("-"))
        except ValueError:
            return Response(
                {"error": "⚠️ Invalid month format. Use YYYY-MM."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        # 🔹 Validate property
        property_obj = get_object_or_404(Property, id=property_id)
        
        # 🔹 Get all units for this property
        units = Unit.objects.filter(property=property_obj)
        
        created_count = 0
        skipped_existing = 0
        skipped_inactive = 0
        created_receipts = []
        
        for unit in units:
            # 🔹 Check for an active contract
            contract = RentalContract.objects.filter(unit=unit, is_active=True).first()
            if not contract:
                skipped_inactive += 1
                continue
            
            # 🔹 Skip if receipt already exists
            exists = Receipt.objects.filter(
                contract=contract,
                issue_date__year=year,
                issue_date__month=month_num,
            ).exists()
            if exists:
                skipped_existing += 1
                continue
            
            # 🔹 Create receipt
            issue_date = timezone.make_aware(datetime(year, month_num, 1))
            receipt = Receipt.objects.create(
                contract=contract,
                monthly_rent=contract.rent_amount,
                previous_water_reading=unit.water_meter_reading,
                previous_electricity_reading=unit.electricity_meter_reading,
                issue_date=issue_date,
                issued_by=request.user  # 🔹 Track who generated the receipt
            )
            
            created_count += 1
            created_receipts.append({
                "month": f"{year}-{month_num:02d}",
                "receipt_number": receipt.receipt_number,
                "property_id": property_obj.id,  # 🔹 Added property_id
                "property": property_obj.name,
                "unit_id": unit.id,  # 🔹 Added unit_id for reference
                "unit": unit.unit_number,
                "customer_id": contract.customer.id,  # 🔹 Added customer_id
                "customer": str(contract.customer),
                "contract_id": contract.id,  # 🔹 Added contract_id
                "amount": str(contract.rent_amount),
                "issue_date": receipt.issue_date.strftime("%Y-%m-%d"),
            })
        
        return Response({
            "status": "✅ Receipts Generation Completed",
            "property_id": property_obj.id,  # 🔹 Added property_id in response
            "property": property_obj.name,
            "month_generated": f"{year}-{month_num:02d}",
            "summary": {
                "total_units_checked": units.count(),
                "receipts_created": created_count,
                "already_existed": skipped_existing,
                "no_active_contract": skipped_inactive,
            },
            "generated_receipts": created_receipts
        }, status=status.HTTP_201_CREATED)


class PropertySystemParameterView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, property_id):
        """
        Get or auto-create System Parameters for a specific property
        """
        system_param, created = SystemParameter.objects.get_or_create(property_id=property_id)
        serializer = SystemParameterSerializer(system_param)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, property_id):
        """
        Update System Parameters for a property
        """
        system_param = get_object_or_404(SystemParameter, property_id=property_id)
        serializer = SystemParameterSerializer(system_param, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, property_id):
        """
        Partial update System Parameters for a property
        """
        system_param = get_object_or_404(SystemParameter, property_id=property_id)
        serializer = SystemParameterSerializer(system_param, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)