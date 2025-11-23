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
from django.db.models import Count, Sum, Avg,Q,Min,Max, F, DecimalField, ExpressionWrapper
from decimal import Decimal
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated



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
    # permission_classes = [IsAuthenticated]

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
        unit.balance = 0  # Reset balance when contract is cancelled
        unit.save(update_fields=["status", "balance"])

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
    

#######################Dashbord analysts


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
    """
    Get overall dashboard summary statistics
    """
    property_id = request.query_params.get('property_id')
    
    # Filter by property if provided
    units_query = Unit.objects.all()
    contracts_query = RentalContract.objects.all()
    receipts_query = Receipt.objects.all()
    
    if property_id:
        units_query = units_query.filter(property_id=property_id)
        contracts_query = contracts_query.filter(unit__property_id=property_id)
        receipts_query = receipts_query.filter(contract__unit__property_id=property_id)
    
    # Total tenants (active contracts)
    total_tenants = contracts_query.filter(is_active=True).values('customer').distinct().count()
    
    # Occupied units
    occupied_units = units_query.filter(status='occupied').count()
    total_units = units_query.count()
    
    # Pending rent (unpaid + partial receipts)
    pending_rent = receipts_query.filter(
        Q(status='unpaid') | Q(status='partial'),
        contract__is_active=True
    ).aggregate(
        total=Sum('monthly_rent') + Sum('electricity_bill') + Sum('water_bill') + 
              Sum('service_charge') + Sum('security_charge') + Sum('other_charges') - Sum('amount_paid')
    )['total'] or Decimal('0.00')
    
    # Contracts expiring in next 30 days
    thirty_days_from_now = timezone.now().date() + timedelta(days=30)
    expiring_contracts = contracts_query.filter(
        is_active=True,
        end_date__lte=thirty_days_from_now,
        end_date__gte=timezone.now().date()
    ).count()
    
    # Vacant units
    vacant_units = units_query.filter(status='vacant').count()
    
    # Total collected this month
    current_month = timezone.now().month
    current_year = timezone.now().year
    monthly_collection = Payment.objects.filter(
        payment_date__month=current_month,
        payment_date__year=current_year
    )
    if property_id:
        monthly_collection = monthly_collection.filter(
            receipt__contract__unit__property_id=property_id
        )
    monthly_collection = monthly_collection.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    
    return Response({
        'total_tenants': total_tenants,
        'occupied_units': occupied_units,
        'total_units': total_units,
        'vacant_units': vacant_units,
        'pending_rent': float(pending_rent),
        'contracts_expiring': expiring_contracts,
        'monthly_collection': float(monthly_collection),
        'occupancy_rate': round((occupied_units / total_units * 100) if total_units > 0 else 0, 2)
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def monthly_rent_collection(request):
    """
    Get monthly rent collection for the last 6-12 months
    """
    property_id = request.query_params.get('property_id')
    months = int(request.query_params.get('months', 6))  # Default 6 months
    
    data = []
    current_date = timezone.now().date()
    
    for i in range(months - 1, -1, -1):
        target_date = current_date - timedelta(days=30 * i)
        month = target_date.month
        year = target_date.year
        
        payments = Payment.objects.filter(
            payment_date__month=month,
            payment_date__year=year
        )
        
        if property_id:
            payments = payments.filter(
                receipt__contract__unit__property_id=property_id
            )
        
        total = payments.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        data.append({
            'month': target_date.strftime('%b'),
            'year': year,
            'amount': float(total)
        })
    
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def occupancy_stats(request):
    """
    Get occupancy statistics (occupied vs vacant units)
    """
    property_id = request.query_params.get('property_id')
    
    units_query = Unit.objects.all()
    if property_id:
        units_query = units_query.filter(property_id=property_id)
    
    occupied = units_query.filter(status='occupied').count()
    vacant = units_query.filter(status='vacant').count()
    
    return Response({
        'occupied': occupied,
        'vacant': vacant,
        'total': occupied + vacant,
        'occupancy_percentage': round((occupied / (occupied + vacant) * 100) if (occupied + vacant) > 0 else 0, 2)
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def payment_methods_breakdown(request):
    """
    Get breakdown of payments by method (Cash, M-Pesa, Bank)
    """
    property_id = request.query_params.get('property_id')
    
    # Get current month or specify date range
    current_month = timezone.now().month
    current_year = timezone.now().year
    
    payments = Payment.objects.filter(
        payment_date__month=current_month,
        payment_date__year=current_year
    )
    
    if property_id:
        payments = payments.filter(
            receipt__contract__unit__property_id=property_id
        )
    
    # Group by method
    cash = payments.filter(method='cash').aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    mpesa = payments.filter(method='mpesa').aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    bank = payments.filter(method='bank').aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    
    return Response({
        'cash': float(cash),
        'mpesa': float(mpesa),
        'bank': float(bank),
        'total': float(cash + mpesa + bank)
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def revenue_vs_expenses(request):
    """
    Get revenue vs expenses for the last 6 months
    """
    property_id = request.query_params.get('property_id')
    months = int(request.query_params.get('months', 6))
    
    data = []
    current_date = timezone.now().date()
    
    for i in range(months - 1, -1, -1):
        target_date = current_date - timedelta(days=30 * i)
        month = target_date.month
        year = target_date.year
        
        # Revenue (payments)
        payments = Payment.objects.filter(
            payment_date__month=month,
            payment_date__year=year
        )
        
        # Expenses
        expenses = Expense.objects.filter(
            expense_date__month=month,
            expense_date__year=year
        )
        
        if property_id:
            payments = payments.filter(
                receipt__contract__unit__property_id=property_id
            )
            expenses = expenses.filter(property_id=property_id)
        
        revenue = payments.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        expense_total = expenses.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        data.append({
            'month': target_date.strftime('%b'),
            'year': year,
            'revenue': float(revenue),
            'expenses': float(expense_total),
            'profit': float(revenue - expense_total)
        })
    
    return Response(data)





# reports haha


class BaseReportView(APIView):
    """Base class with common filtering logic"""
    permission_classes = [IsAuthenticated]
    
    def get_date_range(self, request):
        """Extract and validate date range from query params"""
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        else:
            start_date = (timezone.now() - timedelta(days=30)).date()
            
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            end_date = timezone.now().date()
            
        return start_date, end_date
    
    def get_property_filter(self, request):
        """Get property filter from query params"""
        property_id = request.query_params.get('property_id')
        if property_id:
            return Q(property_id=property_id)
        return Q()


# ==================== FINANCIAL REPORTS ====================

class TotalRevenueReportView(BaseReportView):
    """
    Total revenue with breakdown by property, payment method, and date range
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        
        properties = Property.objects.filter(is_active=True)
        
        comparison_data = []
        
        for prop in properties:
            # Units
            units = Unit.objects.filter(property=prop)
            total_units = units.count()
            occupied = units.filter(status='occupied').count()
            occupancy_rate = (occupied / total_units * 100) if total_units > 0 else 0
            
            # Revenue
            revenue = Payment.objects.filter(
                receipt__contract__unit__property=prop,
                payment_date__range=[start_date, end_date]
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # Expenses
            expenses = Expense.objects.filter(
                property=prop,
                expense_date__range=[start_date, end_date]
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # Outstanding
            outstanding = units.aggregate(total=Sum('balance'))['total'] or Decimal('0.00')
            
            # Active contracts
            active_contracts = RentalContract.objects.filter(
                unit__property=prop,
                is_active=True
            ).count()
            
            # Expected revenue
            expected = RentalContract.objects.filter(
                unit__property=prop,
                is_active=True
            ).aggregate(total=Sum('rent_amount'))['total'] or Decimal('0.00')
            
            # Collection rate
            collection_rate = (revenue / expected * 100) if expected > 0 else 0
            
            comparison_data.append({
                'property_id': prop.id,
                'property_name': prop.name,
                'address': prop.address,
                'units': {
                    'total': total_units,
                    'occupied': occupied,
                    'vacant': total_units - occupied,
                    'occupancy_rate': round(occupancy_rate, 2)
                },
                'financial': {
                    'revenue': revenue,
                    'expenses': expenses,
                    'net_profit': revenue - expenses,
                    'outstanding': outstanding,
                    'expected_monthly_revenue': expected,
                    'collection_rate': round(collection_rate, 2)
                },
                'contracts': {
                    'active': active_contracts
                }
            })
        
        # Overall totals
        totals = {
            'total_properties': len(comparison_data),
            'total_units': sum(p['units']['total'] for p in comparison_data),
            'total_occupied': sum(p['units']['occupied'] for p in comparison_data),
            'total_revenue': sum(p['financial']['revenue'] for p in comparison_data),
            'total_expenses': sum(p['financial']['expenses'] for p in comparison_data),
            'total_outstanding': sum(p['financial']['outstanding'] for p in comparison_data)
        }
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'totals': totals,
            'properties': comparison_data
        })
        property_id = request.query_params.get('property_id')
        
        # Base query
        payments_query = Payment.objects.filter(
            payment_date__range=[start_date, end_date]
        ).select_related('receipt__contract__unit__property')
        
        # Apply property filter
        if property_id:
            payments_query = payments_query.filter(
                receipt__contract__unit__property_id=property_id
            )
        
        # Total revenue
        total_revenue = payments_query.aggregate(
            total=Sum('amount')
        )['total'] or Decimal('0.00')
        
        # Revenue by property
        revenue_by_property = payments_query.values(
            'receipt__contract__unit__property__id',
            'receipt__contract__unit__property__name'
        ).annotate(
            total_revenue=Sum('amount'),
            payment_count=Count('id')
        ).order_by('-total_revenue')
        
        # Revenue by payment method
        revenue_by_method = payments_query.values('method').annotate(
            total=Sum('amount'),
            count=Count('id')
        ).order_by('-total')
        
        # Monthly breakdown
        monthly_revenue = payments_query.extra(
            select={'month': "DATE_TRUNC('month', payment_date)"}
        ).values('month').annotate(
            total=Sum('amount')
        ).order_by('month')
        
        return Response({
            'period': {
                'start_date': start_date,
                'end_date': end_date
            },
            'total_revenue': total_revenue,
            'revenue_by_property': revenue_by_property,
            'revenue_by_method': revenue_by_method,
            'monthly_breakdown': monthly_revenue
        })


class OutstandingBalancesReportView(BaseReportView):
    """
    All units with outstanding balances
    Query params: ?property_id=1&min_balance=1000&status=occupied
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        min_balance = request.query_params.get('min_balance', 0)
        unit_status = request.query_params.get('status')  # vacant/occupied
        
        # Base query - units with balance > 0
        units_query = Unit.objects.filter(
            balance__gt=0
        ).select_related('property', 'tenant')
        
        # Apply filters
        if property_id:
            units_query = units_query.filter(property_id=property_id)
        
        if min_balance:
            units_query = units_query.filter(balance__gte=Decimal(min_balance))
        
        if unit_status:
            units_query = units_query.filter(status=unit_status)
        
        # Get detailed info
        outstanding_units = units_query.values(
            'id',
            'unit_number',
            'property__name',
            'tenant__first_name',
            'tenant__last_name',
            'tenant__phone_number',
            'balance',
            'total_billed',
            'total_paid',
            'status'
        ).order_by('-balance')
        
        # Summary statistics
        summary = units_query.aggregate(
            total_outstanding=Sum('balance'),
            total_units=Count('id'),
            avg_balance=Avg('balance')
        )
        
        # Breakdown by property
        by_property = units_query.values(
            'property__id',
            'property__name'
        ).annotate(
            outstanding=Sum('balance'),
            unit_count=Count('id')
        ).order_by('-outstanding')
        
        return Response({
            'summary': summary,
            'by_property': by_property,
            'units': outstanding_units
        })


class PaymentCollectionReportView(BaseReportView):
    """
    Payment collections over time with trends
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31&group_by=day
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        group_by = request.query_params.get('group_by', 'day')  # day, week, month
        
        # Base query
        payments = Payment.objects.filter(
            payment_date__range=[start_date, end_date]
        ).select_related('receipt__contract__unit__property')
        
        if property_id:
            payments = payments.filter(
                receipt__contract__unit__property_id=property_id
            )
        
        # Group by period
        if group_by == 'day':
            trunc_func = "DATE_TRUNC('day', payment_date)"
        elif group_by == 'week':
            trunc_func = "DATE_TRUNC('week', payment_date)"
        else:  # month
            trunc_func = "DATE_TRUNC('month', payment_date)"
        
        collections = payments.extra(
            select={'period': trunc_func}
        ).values('period').annotate(
            total_collected=Sum('amount'),
            transaction_count=Count('id'),
            avg_payment=Avg('amount')
        ).order_by('period')
        
        # Payment method breakdown
        by_method = payments.values('method').annotate(
            total=Sum('amount'),
            count=Count('id')
        )
        
        # Top payers
        top_payers = payments.values(
            'receipt__contract__customer__first_name',
            'receipt__contract__customer__last_name',
            'receipt__contract__customer__phone_number'
        ).annotate(
            total_paid=Sum('amount'),
            payment_count=Count('id')
        ).order_by('-total_paid')[:10]
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'collections': collections,
            'by_method': by_method,
            'top_payers': top_payers
        })


class RentRollReportView(BaseReportView):
    """
    Current rent roll - all active contracts
    Query params: ?property_id=1&unit_type=one_bedroom
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        unit_type = request.query_params.get('unit_type')
        
        # Active contracts
        contracts = RentalContract.objects.filter(
            is_active=True
        ).select_related(
            'customer', 'unit__property'
        )
        
        if property_id:
            contracts = contracts.filter(unit__property_id=property_id)
        
        if unit_type:
            contracts = contracts.filter(unit__unit_type=unit_type)
        
        # Detailed rent roll
        rent_roll = contracts.values(
            'contract_number',
            'customer__first_name',
            'customer__last_name',
            'customer__phone_number',
            'unit__unit_number',
            'unit__property__name',
            'unit__unit_type',
            'rent_amount',
            'start_date',
            'end_date',
            'unit__balance'
        ).order_by('unit__property__name', 'unit__unit_number')
        
        # Summary
        summary = contracts.aggregate(
            total_units=Count('id'),
            total_monthly_rent=Sum('rent_amount'),
            total_outstanding=Sum('unit__balance')
        )
        
        # By property
        by_property = contracts.values(
            'unit__property__id',
            'unit__property__name'
        ).annotate(
            unit_count=Count('id'),
            monthly_rent=Sum('rent_amount'),
            outstanding=Sum('unit__balance')
        ).order_by('unit__property__name')
        
        return Response({
            'summary': summary,
            'by_property': by_property,
            'rent_roll': rent_roll
        })


class DepositTrackingReportView(BaseReportView):
    """
    Track all deposits collected and status
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        # Get all receipts with deposits in date range
        receipts = Receipt.objects.filter(
            issue_date__range=[start_date, end_date]
        ).filter(
            Q(rental_deposit__gt=0) | 
            Q(water_deposit__gt=0) | 
            Q(electricity_deposit__gt=0)
        ).select_related('contract__customer', 'contract__unit__property')
        
        if property_id:
            receipts = receipts.filter(contract__unit__property_id=property_id)
        
        # Calculate totals
        deposit_summary = receipts.aggregate(
            total_rental_deposits=Sum('rental_deposit'),
            total_water_deposits=Sum('water_deposit'),
            total_electricity_deposits=Sum('electricity_deposit')
        )
        
        # Add grand total
        deposit_summary['grand_total'] = sum([
            deposit_summary['total_rental_deposits'] or 0,
            deposit_summary['total_water_deposits'] or 0,
            deposit_summary['total_electricity_deposits'] or 0
        ])
        
        # Detailed breakdown
        deposits_detail = receipts.values(
            'contract__customer__first_name',
            'contract__customer__last_name',
            'contract__unit__unit_number',
            'contract__unit__property__name',
            'rental_deposit',
            'water_deposit',
            'electricity_deposit',
            'issue_date',
            'contract__is_active'
        ).order_by('-issue_date')
        
        # By property
        by_property = receipts.values(
            'contract__unit__property__id',
            'contract__unit__property__name'
        ).annotate(
            rental_deposits=Sum('rental_deposit'),
            water_deposits=Sum('water_deposit'),
            electricity_deposits=Sum('electricity_deposit')
        ).order_by('contract__unit__property__name')
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': deposit_summary,
            'by_property': by_property,
            'deposits': deposits_detail
        })


class ExpenseAnalysisReportView(BaseReportView):
    """
    Expense analysis by property and time period
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        # Base query
        expenses = Expense.objects.filter(
            expense_date__range=[start_date, end_date]
        ).select_related('property', 'recorded_by')
        
        if property_id:
            expenses = expenses.filter(property_id=property_id)
        
        # Summary
        summary = expenses.aggregate(
            total_expenses=Sum('amount'),
            expense_count=Count('id'),
            avg_expense=Avg('amount')
        )
        
        # By property
        by_property = expenses.values(
            'property__id',
            'property__name'
        ).annotate(
            total=Sum('amount'),
            count=Count('id')
        ).order_by('-total')
        
        # Monthly trend
        monthly = expenses.extra(
            select={'month': "DATE_TRUNC('month', expense_date)"}
        ).values('month').annotate(
            total=Sum('amount'),
            count=Count('id')
        ).order_by('month')
        
        # Detailed expenses
        expense_list = expenses.values(
            'id',
            'property__name',
            'description',
            'amount',
            'expense_date',
            'recorded_by__username'
        ).order_by('-expense_date')
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': summary,
            'by_property': by_property,
            'monthly_trend': monthly,
            'expenses': expense_list
        })


class ProfitLossReportView(BaseReportView):
    """
    Profit & Loss statement
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        # Income (Payments)
        payments = Payment.objects.filter(
            payment_date__range=[start_date, end_date]
        )
        if property_id:
            payments = payments.filter(
                receipt__contract__unit__property_id=property_id
            )
        
        total_income = payments.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Expenses
        expenses = Expense.objects.filter(
            expense_date__range=[start_date, end_date]
        )
        if property_id:
            expenses = expenses.filter(property_id=property_id)
        
        total_expenses = expenses.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Net profit
        net_profit = total_income - total_expenses
        profit_margin = (net_profit / total_income * 100) if total_income > 0 else 0
        
        # Breakdown by property if no filter
        if not property_id:
            by_property = []
            properties = Property.objects.filter(is_active=True)
            
            for prop in properties:
                prop_income = Payment.objects.filter(
                    payment_date__range=[start_date, end_date],
                    receipt__contract__unit__property=prop
                ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
                
                prop_expenses = Expense.objects.filter(
                    expense_date__range=[start_date, end_date],
                    property=prop
                ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
                
                by_property.append({
                    'property_id': prop.id,
                    'property_name': prop.name,
                    'income': prop_income,
                    'expenses': prop_expenses,
                    'profit': prop_income - prop_expenses
                })
        else:
            by_property = None
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'total_income': total_income,
            'total_expenses': total_expenses,
            'net_profit': net_profit,
            'profit_margin_percentage': round(profit_margin, 2),
            'by_property': by_property
        })

class DefaultersReportView(BaseReportView):
    """
    Tenants with overdue balances
    Query params: ?property_id=1&min_balance=500&days_overdue=7
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        property_id = request.query_params.get('property_id')
        min_balance = Decimal(request.query_params.get('min_balance', '0'))
        days_overdue = int(request.query_params.get('days_overdue', '0'))
        
        # Get occupied units with balances
        units = Unit.objects.filter(
            balance__gt=min_balance,
            status='occupied'
        ).select_related('property')
        
        if property_id:
            units = units.filter(property_id=property_id)

        defaulters = []

        for unit in units:
            # 🔥 Get active contract (correct way to get tenant)
            active_contract = unit.contracts.filter(is_active=True).select_related("customer").first()
            tenant = active_contract.customer if active_contract else None
            
            # Identify unpaid receipts
            unpaid_receipts = Receipt.objects.filter(
                contract__unit=unit,
                contract__is_active=True,
                status__in=['unpaid', 'partial']
            ).order_by('issue_date')
            
            if not unpaid_receipts.exists():
                continue

            oldest_unpaid = unpaid_receipts.first()
            days_outstanding = (timezone.now().date() - oldest_unpaid.issue_date.date()).days

            if days_outstanding >= days_overdue:
                defaulters.append({
                    'unit_number': unit.unit_number,
                    'property': unit.property.name,

                    # 🔥 SAFE TENANT ACCESS
                    'tenant_name': (
                        f"{tenant.first_name} {tenant.last_name}"
                        if tenant else "N/A"
                    ),

                    'phone': tenant.phone_number if tenant else "N/A",
                    'balance': unit.balance,
                    'days_overdue': days_outstanding,
                    'oldest_unpaid_date': oldest_unpaid.issue_date
                })
        
        # Sort by balance descending
        defaulters.sort(key=lambda x: x['balance'], reverse=True)
        
        # Summary section
        total_defaulters = len(defaulters)
        total_amount_overdue = sum(item['balance'] for item in defaulters)

        summary = {
            'total_defaulters': total_defaulters,
            'total_amount_overdue': total_amount_overdue,
            'avg_overdue_amount': (total_amount_overdue / total_defaulters) if total_defaulters else 0
        }

        return Response({
            'summary': summary,
            'defaulters': defaulters
        })

class PaymentMethodAnalysisView(BaseReportView):
    """
    Analysis of payment methods usage
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        payments = Payment.objects.filter(
            payment_date__range=[start_date, end_date]
        )
        
        if property_id:
            payments = payments.filter(
                receipt__contract__unit__property_id=property_id
            )
        
        # By method
        by_method = payments.values('method').annotate(
            total_amount=Sum('amount'),
            transaction_count=Count('id'),
            avg_transaction=Avg('amount')
        ).order_by('-total_amount')
        
        # Calculate percentages
        total = payments.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        for item in by_method:
            item['percentage'] = (item['total_amount'] / total * 100) if total > 0 else 0
        
        # Trend over time
        monthly_by_method = payments.extra(
            select={'month': "DATE_TRUNC('month', payment_date)"}
        ).values('month', 'method').annotate(
            total=Sum('amount')
        ).order_by('month', 'method')
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'by_method': by_method,
            'monthly_trend': monthly_by_method
        })


class RevenueForecastReportView(BaseReportView):
    """
    Revenue forecast based on active contracts
    Query params: ?property_id=1&months=3
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        months = int(request.query_params.get('months', '3'))
        
        # Active contracts
        contracts = RentalContract.objects.filter(is_active=True)
        
        if property_id:
            contracts = contracts.filter(unit__property_id=property_id)
        
        # Calculate monthly forecast
        monthly_rent = contracts.aggregate(total=Sum('rent_amount'))['total'] or Decimal('0.00')
        
        forecast = {
            'expected_monthly_revenue': monthly_rent,
            'forecast_period_months': months,
            'total_forecast': monthly_rent * months,
            'active_contracts': contracts.count()
        }
        
        # By property
        if not property_id:
            by_property = contracts.values(
                'unit__property__id',
                'unit__property__name'
            ).annotate(
                monthly_rent=Sum('rent_amount'),
                contract_count=Count('id')
            )
            forecast['by_property'] = by_property
        
        return Response(forecast)


# ==================== OCCUPANCY & UNIT REPORTS ====================

class OccupancyRateReportView(BaseReportView):
    """
    Occupancy rate by property
    Query params: ?property_id=1
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        
        units = Unit.objects.all()
        
        if property_id:
            units = units.filter(property_id=property_id)
        
        # Overall stats
        total_units = units.count()
        occupied_units = units.filter(status='occupied').count()
        vacant_units = units.filter(status='vacant').count()
        occupancy_rate = (occupied_units / total_units * 100) if total_units > 0 else 0
        
        # By property
        by_property = Unit.objects.values(
            'property__id',
            'property__name'
        ).annotate(
            total_units=Count('id'),
            occupied=Count('id', filter=Q(status='occupied')),
            vacant=Count('id', filter=Q(status='vacant'))
        ).order_by('property__name')
        
        # Add occupancy rate to each property
        for item in by_property:
            item['occupancy_rate'] = (item['occupied'] / item['total_units'] * 100) if item['total_units'] > 0 else 0
        
        # By unit type
        by_unit_type = units.values('unit_type').annotate(
            total=Count('id'),
            occupied=Count('id', filter=Q(status='occupied')),
            vacant=Count('id', filter=Q(status='vacant'))
        ).order_by('unit_type')
        
        for item in by_unit_type:
            item['occupancy_rate'] = (item['occupied'] / item['total'] * 100) if item['total'] > 0 else 0
        
        return Response({
            'overall': {
                'total_units': total_units,
                'occupied': occupied_units,
                'vacant': vacant_units,
                'occupancy_rate': round(occupancy_rate, 2)
            },
            'by_property': by_property,
            'by_unit_type': by_unit_type
        })

class UnitPerformanceReportView(BaseReportView):
    """
    Performance metrics for each unit
    Query params: ?property_id=1&order_by=revenue
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        property_id = request.query_params.get('property_id')
        order_by = request.query_params.get('order_by', 'revenue')  # revenue, balance, occupancy
        
        # Remove invalid tenant select_related
        units = Unit.objects.select_related('property')
        
        if property_id:
            units = units.filter(property_id=property_id)
        
        unit_performance = []
        
        for unit in units:
            # Revenue for unit
            revenue = Payment.objects.filter(
                receipt__contract__unit=unit
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # Get active contract (correct way to get a tenant)
            active_contract = unit.contracts.filter(is_active=True).select_related('customer').first()
            tenant = active_contract.customer if active_contract else None
            
            unit_performance.append({
                'unit_id': unit.id,
                'unit_number': unit.unit_number,
                'property': unit.property.name,
                'unit_type': unit.get_unit_type_display(),
                'status': unit.status,
                'rent_amount': unit.rent_amount,
                'total_revenue': revenue,
                'balance': unit.balance,

                # 🔥 FIXED tenant retrieval
                'tenant': f"{tenant.first_name} {tenant.last_name}" if tenant else None,

                'contract_active': bool(active_contract)
            })
        
        # Sorting
        if order_by == 'revenue':
            unit_performance.sort(key=lambda x: x['total_revenue'], reverse=True)
        elif order_by == 'balance':
            unit_performance.sort(key=lambda x: x['balance'], reverse=True)
        
        return Response({
            'units': unit_performance,
            'total_units': len(unit_performance)
        })


class VacancyDurationReportView(BaseReportView):
    """
    Track how long units have been vacant
    Query params: ?property_id=1&min_days=30
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        min_days = int(request.query_params.get('min_days', '0'))
        
        # Get vacant units
        vacant_units = Unit.objects.filter(
            status='vacant'
        ).select_related('property')
        
        if property_id:
            vacant_units = vacant_units.filter(property_id=property_id)
        
        vacancy_data = []
        
        for unit in vacant_units:
            # Find last active contract
            last_contract = RentalContract.objects.filter(
                unit=unit
            ).order_by('-end_date').first()
            
            if last_contract and last_contract.end_date:
                days_vacant = (timezone.now().date() - last_contract.end_date).days
            else:
                # Unit never rented or no end date
                days_vacant = (timezone.now().date() - unit.created_at.date()).days
            
            if days_vacant >= min_days:
                vacancy_data.append({
                    'unit_number': unit.unit_number,
                    'property': unit.property.name,
                    'unit_type': unit.get_unit_type_display(),
                    'rent_amount': unit.rent_amount,
                    'days_vacant': days_vacant,
                    'last_tenant': f"{last_contract.customer.first_name} {last_contract.customer.last_name}" if last_contract else None,
                    'vacancy_start': last_contract.end_date if last_contract else unit.created_at.date()
                })
        
        # Sort by days vacant
        vacancy_data.sort(key=lambda x: x['days_vacant'], reverse=True)
        
        # Summary
        summary = {
            'total_vacant_units': len(vacancy_data),
            'avg_vacancy_days': sum(u['days_vacant'] for u in vacancy_data) / len(vacancy_data) if vacancy_data else 0,
            'longest_vacancy': max(u['days_vacant'] for u in vacancy_data) if vacancy_data else 0
        }
        
        return Response({
            'summary': summary,
            'vacant_units': vacancy_data
        })


class UnitTypeAnalysisView(BaseReportView):
    """
    Performance analysis by unit type
    Query params: ?property_id=1
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        
        units = Unit.objects.all()
        
        if property_id:
            units = units.filter(property_id=property_id)
        
        analysis = []
        
        for unit_type_code, unit_type_label in Unit.UnitType.choices:
            type_units = units.filter(unit_type=unit_type_code)
            
            if not type_units.exists():
                continue
            
            # Stats
            total = type_units.count()
            occupied = type_units.filter(status='occupied').count()
            avg_rent = type_units.aggregate(avg=Avg('rent_amount'))['avg'] or 0
            total_revenue = Payment.objects.filter(
                receipt__contract__unit__unit_type=unit_type_code
            ).aggregate(total=Sum('amount'))['total'] or 0
            
            analysis.append({
                'unit_type': unit_type_label,
                'total_units': total,
                'occupied': occupied,
                'vacant': total - occupied,
                'occupancy_rate': (occupied / total * 100) if total > 0 else 0,
                'avg_rent': avg_rent,
                'total_revenue': total_revenue
            })
        
        return Response({'analysis': analysis})


class TenantMovementReportView(BaseReportView):
    """
    Track tenant move-ins and move-outs
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        # Move-ins (contracts starting in period)
        move_ins = RentalContract.objects.filter(
            start_date__range=[start_date, end_date]
        ).select_related('customer', 'unit__property')
        
        if property_id:
            move_ins = move_ins.filter(unit__property_id=property_id)
        
        # Move-outs (contracts ending in period)
        move_outs = RentalContract.objects.filter(
            end_date__range=[start_date, end_date]
        ).select_related('customer', 'unit__property')
        
        if property_id:
            move_outs = move_outs.filter(unit__property_id=property_id)
        
        move_ins_data = move_ins.values(
            'customer__first_name',
            'customer__last_name',
            'unit__unit_number',
            'unit__property__name',
            'start_date',
            'rent_amount'
        ).order_by('-start_date')
        
        move_outs_data = move_outs.values(
            'customer__first_name',
            'customer__last_name',
            'unit__unit_number',
            'unit__property__name',
            'end_date',
            'rent_amount'
        ).order_by('-end_date')
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': {
                'total_move_ins': move_ins.count(),
                'total_move_outs': move_outs.count(),
                'net_change': move_ins.count() - move_outs.count()
            },
            'move_ins': move_ins_data,
            'move_outs': move_outs_data
        })


class RentPricingAnalysisView(BaseReportView):
    """
    Rent pricing analysis by unit type and property
    Query params: ?property_id=1
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        property_id = request.query_params.get('property_id')
        
        units = Unit.objects.all()
        
        if property_id:
            units = units.filter(property_id=property_id)
        
        # Overall pricing stats
        overall = units.aggregate(
            avg_rent=Avg('rent_amount'),
            min_rent=Min('rent_amount'),
            max_rent=Max('rent_amount')
        )
        
        # By unit type
        by_type = units.values('unit_type').annotate(
            avg_rent=Avg('rent_amount'),
            min_rent=Min('rent_amount'),
            max_rent=Max('rent_amount'),
            unit_count=Count('id')
        ).order_by('unit_type')
        
        # By property
        by_property = units.values(
            'property__id',
            'property__name'
        ).annotate(
            avg_rent=Avg('rent_amount'),
            min_rent=Min('rent_amount'),
            max_rent=Max('rent_amount'),
            unit_count=Count('id')
        ).order_by('property__name')
        
        # By property and unit type (matrix)
        pricing_matrix = units.values(
            'property__name',
            'unit_type'
        ).annotate(
            avg_rent=Avg('rent_amount'),
            count=Count('id')
        ).order_by('property__name', 'unit_type')
        
        return Response({
            'overall': overall,
            'by_unit_type': by_type,
            'by_property': by_property,
            'pricing_matrix': pricing_matrix
        })


class UnitUtilizationReportView(BaseReportView):
    """
    Historical occupancy trends
    Query params: ?property_id=1&months=12
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        months = int(request.query_params.get('months', '12'))
        
        # Current occupancy
        units = Unit.objects.all()
        if property_id:
            units = units.filter(property_id=property_id)
        
        current_occupancy = {
            'total': units.count(),
            'occupied': units.filter(status='occupied').count(),
            'vacant': units.filter(status='vacant').count()
        }
        current_occupancy['rate'] = (
            current_occupancy['occupied'] / current_occupancy['total'] * 100
        ) if current_occupancy['total'] > 0 else 0
        
        # Historical data (based on contract activity)
        historical = []
        for i in range(months):
            month_start = (timezone.now() - timedelta(days=30*i)).date()
            
            # Count active contracts in that month
            active_contracts = RentalContract.objects.filter(
                start_date__lte=month_start,
                is_active=True
            ).filter(
                Q(end_date__gte=month_start) | Q(end_date__isnull=True)
            )
            
            if property_id:
                active_contracts = active_contracts.filter(unit__property_id=property_id)
            
            occupied = active_contracts.count()
            total = units.count()
            
            historical.append({
                'month': month_start.strftime('%Y-%m'),
                'occupied': occupied,
                'total': total,
                'occupancy_rate': (occupied / total * 100) if total > 0 else 0
            })
        
        historical.reverse()
        
        return Response({
            'current': current_occupancy,
            'historical': historical
        })


class AvailableUnitsReportView(BaseReportView):
    """
    List of all available (vacant) units
    Query params: ?property_id=1&unit_type=one_bedroom&max_rent=50000
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        unit_type = request.query_params.get('unit_type')
        max_rent = request.query_params.get('max_rent')
        
        # Vacant units
        available = Unit.objects.filter(
            status='vacant'
        ).select_related('property')
        
        if property_id:
            available = available.filter(property_id=property_id)
        
        if unit_type:
            available = available.filter(unit_type=unit_type)
        
        if max_rent:
            available = available.filter(rent_amount__lte=Decimal(max_rent))
        
        units_data = available.values(
            'id',
            'unit_number',
            'property__name',
            'property__address',
            'unit_type',
            'rent_amount',
            'water_meter_reading',
            'electricity_meter_reading'
        ).order_by('property__name', 'unit_number')
        
        # Summary
        summary = {
            'total_available': available.count(),
            'properties': available.values('property__name').distinct().count()
        }
        
        # By property
        by_property = available.values(
            'property__id',
            'property__name'
        ).annotate(
            available_count=Count('id'),
            avg_rent=Avg('rent_amount')
        ).order_by('property__name')
        
        return Response({
            'summary': summary,
            'by_property': by_property,
            'units': units_data
        })


# ==================== TENANT & CUSTOMER REPORTS ====================

class TenantDirectoryReportView(BaseReportView):
    """
    Complete tenant directory
    Query params: ?property_id=1&is_active=true
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        is_active = request.query_params.get('is_active')
        
        customers = Customer.objects.select_related('unit__property')
        
        if property_id:
            customers = customers.filter(unit__property_id=property_id)
        
        if is_active is not None:
            is_active_bool = is_active.lower() == 'true'
            customers = customers.filter(is_active=is_active_bool)
        
        directory = customers.values(
            'id',
            'first_name',
            'last_name',
            'phone_number',
            'email',
            'id_number',
            'unit__unit_number',
            'unit__property__name',
            'move_in_date',
            'is_active'
        ).order_by('unit__property__name', 'last_name')
        
        # Summary
        summary = {
            'total_tenants': customers.count(),
            'active': customers.filter(is_active=True).count(),
            'inactive': customers.filter(is_active=False).count()
        }
        
        return Response({
            'summary': summary,
            'directory': directory
        })

class TenantPaymentHistoryView(BaseReportView):
    permission_classes = [IsAuthenticated]

    def get(self, request, tenant_id):
        start_date, end_date = self.get_date_range(request)

        try:
            customer = Customer.objects.get(id=tenant_id)
        except Customer.DoesNotExist:
            return Response({'error': 'Tenant not found'}, status=404)

        # Compute total billed for each receipt
        payments = Payment.objects.filter(
            receipt__contract__customer=customer,
            payment_date__range=[start_date, end_date]
        ).select_related('receipt').annotate(
            total_amount=(
                F('receipt__monthly_rent') +
                F('receipt__rental_deposit') +
                F('receipt__electricity_deposit') +
                F('receipt__electricity_bill') +
                F('receipt__water_deposit') +
                F('receipt__water_bill') +
                F('receipt__service_charge') +
                F('receipt__security_charge') +
                F('receipt__previous_balance') +
                F('receipt__other_charges')
            )
        ).order_by('-payment_date')

        payment_history = payments.values(
            'id',
            'amount',
            'payment_date',
            'method',
            'reference',
            'receipt__receipt_number',
            'receipt__status',
            'total_amount'
        )

        summary = {
            'tenant_name': f"{customer.first_name} {customer.last_name}",
            'phone': customer.phone_number,
            'unit': customer.unit.unit_number if customer.unit else None,
            'total_paid': payments.aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'payment_count': payments.count(),
            'current_balance': customer.unit.balance if customer.unit else Decimal('0.00')
        }

        return Response({
            'summary': summary,
            'payment_history': payment_history
        })
    

class TenantArrearsAgingView(BaseReportView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        property_id = request.query_params.get('property_id')

        units = Unit.objects.filter(
            balance__gt=0,
            status='occupied'
        ).select_related('property', 'tenant')

        if property_id:
            units = units.filter(property_id=property_id)

        aging_data = {
            '0-30_days': [],
            '31-60_days': [],
            '61-90_days': [],
            '90+_days': []
        }

        totals = {
            '0-30_days': Decimal('0.00'),
            '31-60_days': Decimal('0.00'),
            '61-90_days': Decimal('0.00'),
            '90+_days': Decimal('0.00')
        }

        for unit in units:
            # 🔥 Skip units with no tenant (to avoid crash)
            try:
                tenant = unit.tenant
            except Unit.tenant.RelatedObjectDoesNotExist:
                continue

            # Find oldest unpaid receipt
            oldest_unpaid = Receipt.objects.filter(
                contract__unit=unit,
                contract__is_active=True,
                status__in=['unpaid', 'partial']
            ).order_by('issue_date').first()

            if oldest_unpaid:
                days_overdue = (timezone.now().date() - oldest_unpaid.issue_date.date()).days

                tenant_info = {
                    'tenant_name': f"{tenant.first_name} {tenant.last_name}",
                    'phone': tenant.phone_number,
                    'unit': unit.unit_number,
                    'property': unit.property.name,
                    'balance': unit.balance,
                    'days_overdue': days_overdue,
                    'oldest_unpaid_date': oldest_unpaid.issue_date.date()
                }

                if days_overdue <= 30:
                    aging_data['0-30_days'].append(tenant_info)
                    totals['0-30_days'] += unit.balance
                elif days_overdue <= 60:
                    aging_data['31-60_days'].append(tenant_info)
                    totals['31-60_days'] += unit.balance
                elif days_overdue <= 90:
                    aging_data['61-90_days'].append(tenant_info)
                    totals['61-90_days'] += unit.balance
                else:
                    aging_data['90+_days'].append(tenant_info)
                    totals['90+_days'] += unit.balance

        return Response({
            'totals': totals,
            'grand_total': sum(totals.values()),
            'aging_details': aging_data
        })



class ContractExpiryReportView(BaseReportView):
    """
    Contracts expiring soon
    Query params: ?property_id=1&days=30
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        days = int(request.query_params.get('days', '30'))
        
        cutoff_date = timezone.now().date() + timedelta(days=days)
        
        expiring = RentalContract.objects.filter(
            is_active=True,
            end_date__lte=cutoff_date,
            end_date__gte=timezone.now().date()
        ).select_related('customer', 'unit__property').order_by('end_date')
        
        if property_id:
            expiring = expiring.filter(unit__property_id=property_id)
        
        contracts_data = expiring.values(
            'contract_number',
            'customer__first_name',
            'customer__last_name',
            'customer__phone_number',
            'unit__unit_number',
            'unit__property__name',
            'end_date',
            'rent_amount',
            'unit__balance'
        )
        
        # Calculate days until expiry for each
        contracts_list = list(contracts_data)
        for contract in contracts_list:
            days_until = (contract['end_date'] - timezone.now().date()).days
            contract['days_until_expiry'] = days_until
        
        return Response({
            'summary': {
                'total_expiring': len(contracts_list),
                'within_7_days': len([c for c in contracts_list if c['days_until_expiry'] <= 7]),
                'within_30_days': len(contracts_list)
            },
            'contracts': contracts_list
        })


class NewTenantReportView(BaseReportView):
    """
    Recently onboarded tenants
    Query params: ?property_id=1&days=30
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        days = int(request.query_params.get('days', '30'))
        
        cutoff_date = timezone.now().date() - timedelta(days=days)
        
        new_tenants = Customer.objects.filter(
            move_in_date__gte=cutoff_date
        ).select_related('unit__property')
        
        if property_id:
            new_tenants = new_tenants.filter(unit__property_id=property_id)
        
        tenants_data = new_tenants.values(
            'first_name',
            'last_name',
            'phone_number',
            'email',
            'unit__unit_number',
            'unit__property__name',
            'move_in_date',
            'unit__rent_amount'
        ).order_by('-move_in_date')
        
        return Response({
            'summary': {
                'total_new_tenants': new_tenants.count(),
                'period_days': days
            },
            'new_tenants': tenants_data
        })


class TenantRetentionReportView(BaseReportView):
    """
    Tenant retention metrics
    Query params: ?property_id=1
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        
        contracts = RentalContract.objects.all()
        
        if property_id:
            contracts = contracts.filter(unit__property_id=property_id)
        
        # Calculate average tenancy duration
        ended_contracts = contracts.filter(end_date__isnull=False)
        
        durations = []
        for contract in ended_contracts:
            duration = (contract.end_date - contract.start_date).days
            durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        # Active vs ended
        active_count = contracts.filter(is_active=True).count()
        ended_count = contracts.filter(is_active=False).count()
        total = active_count + ended_count
        
        retention_rate = (active_count / total * 100) if total > 0 else 0
        
        # Tenancy length distribution
        distribution = {
            '0-6_months': len([d for d in durations if d <= 180]),
            '6-12_months': len([d for d in durations if 180 < d <= 365]),
            '1-2_years': len([d for d in durations if 365 < d <= 730]),
            '2+_years': len([d for d in durations if d > 730])
        }
        
        return Response({
            'average_tenancy_days': round(avg_duration, 2),
            'average_tenancy_months': round(avg_duration / 30, 2),
            'active_contracts': active_count,
            'ended_contracts': ended_count,
            'retention_rate': round(retention_rate, 2),
            'tenancy_distribution': distribution
        })


# ==================== UTILITY & MAINTENANCE REPORTS ====================

class UtilityConsumptionReportView(BaseReportView):
    """
    Water and electricity consumption by unit
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        receipts = Receipt.objects.filter(
            issue_date__range=[start_date, end_date]
        ).select_related('contract__unit__property')
        
        if property_id:
            receipts = receipts.filter(contract__unit__property_id=property_id)
        
        consumption_data = []
        
        for receipt in receipts:
            water_consumed = receipt.current_water_reading - receipt.previous_water_reading
            electricity_consumed = receipt.current_electricity_reading - receipt.previous_electricity_reading
            
            if water_consumed > 0 or electricity_consumed > 0:
                consumption_data.append({
                    'unit': receipt.contract.unit.unit_number,
                    'property': receipt.contract.unit.property.name,
                    'tenant': f"{receipt.contract.customer.first_name} {receipt.contract.customer.last_name}",
                    'issue_date': receipt.issue_date.date(),
                    'water_consumed': water_consumed,
                    'electricity_consumed': electricity_consumed,
                    'water_bill': receipt.water_bill,
                    'electricity_bill': receipt.electricity_bill
                })
        
        # Summary
        total_water = sum(item['water_consumed'] for item in consumption_data)
        total_electricity = sum(item['electricity_consumed'] for item in consumption_data)
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': {
                'total_water_consumed': total_water,
                'total_electricity_consumed': total_electricity,
                'avg_water_per_unit': total_water / len(consumption_data) if consumption_data else 0,
                'avg_electricity_per_unit': total_electricity / len(consumption_data) if consumption_data else 0
            },
            'consumption': consumption_data
        })


class UtilityRevenueReportView(BaseReportView):
    """
    Revenue from utility bills
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        receipts = Receipt.objects.filter(
            issue_date__range=[start_date, end_date]
        )
        
        if property_id:
            receipts = receipts.filter(contract__unit__property_id=property_id)
        
        # Aggregate utility revenue
        utility_revenue = receipts.aggregate(
            total_water_bills=Sum('water_bill'),
            total_electricity_bills=Sum('electricity_bill'),
            total_water_deposits=Sum('water_deposit'),
            total_electricity_deposits=Sum('electricity_deposit')
        )
        
        # Calculate totals
        water_total = (utility_revenue['total_water_bills'] or 0) + (utility_revenue['total_water_deposits'] or 0)
        electricity_total = (utility_revenue['total_electricity_bills'] or 0) + (utility_revenue['total_electricity_deposits'] or 0)
        grand_total = water_total + electricity_total
        
        # Monthly breakdown
        monthly = receipts.extra(
            select={'month': "DATE_TRUNC('month', issue_date)"}
        ).values('month').annotate(
            water_revenue=Sum('water_bill'),
            electricity_revenue=Sum('electricity_bill')
        ).order_by('month')
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': {
                'water_revenue': water_total,
                'electricity_revenue': electricity_total,
                'grand_total': grand_total
            },
            'monthly_breakdown': monthly
        })


class MaintenanceRequestReportView(BaseReportView):
    """
    Maintenance requests tracking
    Query params: ?property_id=1&status=pending&start_date=2024-01-01
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        req_status = request.query_params.get('status')
        
        requests = MaintenanceRequest.objects.filter(
            reported_date__range=[start_date, end_date]
        ).select_related('unit__property', 'customer')
        
        if property_id:
            requests = requests.filter(unit__property_id=property_id)
        
        if req_status:
            requests = requests.filter(status=req_status)
        
        # Calculate response times
        request_data = []
        for req in requests:
            response_time = None
            if req.resolved_date:
                response_time = (req.resolved_date - req.reported_date).days
            
            request_data.append({
                'id': req.id,
                'unit': req.unit.unit_number,
                'property': req.unit.property.name,
                'tenant': f"{req.customer.first_name} {req.customer.last_name}" if req.customer else None,
                'description': req.description,
                'status': req.status,
                'reported_date': req.reported_date,
                'resolved_date': req.resolved_date,
                'response_time_days': response_time
            })
        
        # Summary
        total = requests.count()
        by_status = requests.values('status').annotate(count=Count('id'))
        
        resolved = requests.filter(status='resolved')
        avg_response_time = None
        if resolved.exists():
            response_times = [
                (r.resolved_date - r.reported_date).days 
                for r in resolved if r.resolved_date
            ]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': {
                'total_requests': total,
                'by_status': by_status,
                'avg_response_time_days': avg_response_time
            },
            'requests': request_data
        })


class MaintenanceCostReportView(BaseReportView):
    """
    Maintenance-related expenses
    Query params: ?property_id=1&start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        start_date, end_date = self.get_date_range(request)
        property_id = request.query_params.get('property_id')
        
        # Filter expenses by description containing maintenance keywords
        maintenance_keywords = ['maintenance', 'repair', 'fix', 'plumbing', 'electrical', 'painting']
        
        q_objects = Q()
        for keyword in maintenance_keywords:
            q_objects |= Q(description__icontains=keyword)
        
        expenses = Expense.objects.filter(
            q_objects,
            expense_date__range=[start_date, end_date]
        ).select_related('property', 'recorded_by')
        
        if property_id:
            expenses = expenses.filter(property_id=property_id)
        
        # Summary
        total_cost = expenses.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # By property
        by_property = expenses.values(
            'property__id',
            'property__name'
        ).annotate(
            total_cost=Sum('amount'),
            expense_count=Count('id')
        ).order_by('-total_cost')
        
        # Detailed list
        expense_list = expenses.values(
            'id',
            'property__name',
            'description',
            'amount',
            'expense_date',
            'recorded_by__username'
        ).order_by('-expense_date')
        
        return Response({
            'period': {'start_date': start_date, 'end_date': end_date},
            'summary': {
                'total_maintenance_cost': total_cost,
                'expense_count': expenses.count()
            },
            'by_property': by_property,
            'expenses': expense_list
        })


# ==================== EXECUTIVE & DASHBOARD REPORTS ====================

class ExecutiveDashboardView(BaseReportView):
    """
    High-level KPIs for executive dashboard
    Query params: ?property_id=1&period=30 (days)
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        property_id = request.query_params.get('property_id')
        period = int(request.query_params.get('period', '30'))
        
        start_date = timezone.now().date() - timedelta(days=period)
        end_date = timezone.now().date()
        
        # Apply property filter
        units_query = Unit.objects.all()
        payments_query = Payment.objects.filter(payment_date__range=[start_date, end_date])
        expenses_query = Expense.objects.filter(expense_date__range=[start_date, end_date])
        
        if property_id:
            units_query = units_query.filter(property_id=property_id)
            payments_query = payments_query.filter(receipt__contract__unit__property_id=property_id)
            expenses_query = expenses_query.filter(property_id=property_id)
        
        # Revenue
        total_revenue = payments_query.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Expenses
        total_expenses = expenses_query.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Net profit
        net_profit = total_revenue - total_expenses
        
        # Outstanding balances
        total_outstanding = units_query.aggregate(total=Sum('balance'))['total'] or Decimal('0.00')
        
        # Occupancy
        total_units = units_query.count()
        occupied = units_query.filter(status='occupied').count()
        occupancy_rate = (occupied / total_units * 100) if total_units > 0 else 0
        
        # Active contracts
        active_contracts = RentalContract.objects.filter(is_active=True)
        if property_id:
            active_contracts = active_contracts.filter(unit__property_id=property_id)
        
        # Expected monthly revenue
        expected_revenue = active_contracts.aggregate(total=Sum('rent_amount'))['total'] or Decimal('0.00')
        
        # Collection rate
        collection_rate = (total_revenue / expected_revenue * 100) if expected_revenue > 0 else 0
        
        # Maintenance requests
        pending_maintenance = MaintenanceRequest.objects.filter(status='pending')
        if property_id:
            pending_maintenance = pending_maintenance.filter(unit__property_id=property_id)
        
        return Response({
            'period': {
                'start_date': start_date,
                'end_date': end_date,
                'days': period
            },
            'financial': {
                'total_revenue': total_revenue,
                'total_expenses': total_expenses,
                'net_profit': net_profit,
                'profit_margin': ((net_profit / total_revenue * 100) if total_revenue > 0 else 0),
                'outstanding_balances': total_outstanding,
                'expected_monthly_revenue': expected_revenue,
                'collection_rate': round(collection_rate, 2)
            },
            'occupancy': {
                'total_units': total_units,
                'occupied': occupied,
                'vacant': total_units - occupied,
                'occupancy_rate': round(occupancy_rate, 2)
            },
            'operations': {
                'active_contracts': active_contracts.count(),
                'pending_maintenance': pending_maintenance.count()
            }
        })


class PropertyComparisonReportView(BaseReportView):
    """
    Side-by-side comparison of all properties
    Query params: ?start_date=2024-01-01&end_date=2024-12-31
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        start_date, end_date = self.get_date_range(request)

        properties = Property.objects.all().order_by('name')

        comparison = []

        for prop in properties:
            # Units under this property
            units = Unit.objects.filter(property=prop)

            total_units = units.count()
            occupied_units = units.filter(status='occupied').count()
            vacant_units = total_units - occupied_units

       # Active contracts under this property
            contracts = RentalContract.objects.filter(
                unit__property=prop,
                is_active=True
            )
            # Rent expected (sum of monthly_rent for active contracts)
            expected_rent = contracts.aggregate(
                total=Sum('rent_amount')
            )['total'] or Decimal('0.00')

            # Payments received within the date range
            payments = Payment.objects.filter(
                receipt__contract__unit__property=prop,
                payment_date__range=[start_date, end_date]
            )

            total_collected = payments.aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00')

            # Total arrears = sum of unit balances
            arrears = units.aggregate(
                total=Sum('balance')
            )['total'] or Decimal('0.00')

            # Occupancy rate
            occupancy_rate = (
                (occupied_units / total_units) * 100
                if total_units > 0 else 0
            )

            # Efficiency: collected / expected
            collection_efficiency = (
                (total_collected / expected_rent) * 100
                if expected_rent > 0 else 0
            )

            comparison.append({
                "property_id": prop.id,
                "property_name": prop.name,

                "total_units": total_units,
                "occupied_units": occupied_units,
                "vacant_units": vacant_units,
                "occupancy_rate": round(occupancy_rate, 2),

                "expected_rent": expected_rent,
                "total_collected": total_collected,
                "collection_efficiency": round(collection_efficiency, 2),
                "arrears": arrears,
            })

        return Response({
            "start_date": start_date,
            "end_date": end_date,
            "comparison": comparison
        })
