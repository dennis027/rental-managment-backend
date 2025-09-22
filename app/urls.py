from django.urls import path
from .views import ActivateAccountView, RegisterView, LoginView,PasswordResetRequestView,PasswordResetConfirmView,PasswordResetCodeCheckView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("activate/<uidb64>/<token>/", ActivateAccountView.as_view(), name="activate"),
    path("reset-password/", PasswordResetRequestView.as_view(), name="reset-password"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("password-reset/check-code/", PasswordResetCodeCheckView.as_view(), name="password-reset-check-code"),
]