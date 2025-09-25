from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import ActivateAccountView, PropertyDetail, PropertyListCreate, RegisterView, LoginView,PasswordResetRequestView,PasswordResetConfirmView,PasswordResetCodeCheckView,LogoutView,ResendActivationWithRateLimitView, UnitDetail, UnitListCreate 

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),  
    path("login/", LoginView.as_view(), name="login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path("activate/<uidb64>/<token>/", ActivateAccountView.as_view(), name="activate"),
    path('resend-activation-limited/', ResendActivationWithRateLimitView.as_view(), name='resend_activation_limited'),
    path("reset-password/", PasswordResetRequestView.as_view(), name="reset-password"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("password-reset/check-code/", PasswordResetCodeCheckView.as_view(), name="password-reset-check-code"),



        # Property APIs
    path("properties/", PropertyListCreate.as_view(), name="property-list-create"),
    path("properties/<int:pk>/", PropertyDetail.as_view(), name="property-detail"),

    # Unit APIs
    path("units/", UnitListCreate.as_view(), name="unit-list-create"),
    path("units/<int:pk>/", UnitDetail.as_view(), name="unit-detail"),
]