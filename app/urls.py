from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import ActivateAccountView, ContractSearchView, CustomerDetail, CustomerListCreate, ExpenseDetailView, ExpenseListCreateView, MaintenanceRequestDetailView, MaintenanceRequestListCreateView, PaymentDetailView, PaymentListCreateView, PropertyUnitsAnalyticsView, PropertyDetail, PropertyListCreate, RegisterView, LoginView,PasswordResetRequestView,PasswordResetConfirmView,PasswordResetCodeCheckView,LogoutView, RentalContractCancel, RentalContractDetail, RentalContractListCreate,ResendActivationWithRateLimitView, UnitDetail, UnitListCreate 

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("api/register/", RegisterView.as_view(), name="register"),  
    path("api/login/", LoginView.as_view(), name="login"),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path("api/activate/<uidb64>/<token>/", ActivateAccountView.as_view(), name="activate"),
    path('api/resend-activation-limited/', ResendActivationWithRateLimitView.as_view(), name='resend_activation_limited'),
    path("api/reset-password/", PasswordResetRequestView.as_view(), name="reset-password"),
    path("api/password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("api/password-reset/check-code/", PasswordResetCodeCheckView.as_view(), name="password-reset-check-code"),



        # Property APIs
    path("api/properties/", PropertyListCreate.as_view(), name="property-list-create"),
    path("api/properties/<int:pk>/", PropertyDetail.as_view(), name="property-detail"),

    # Unit APIs
    path("api/units/", UnitListCreate.as_view(), name="unit-list-create"),
    path("api/units/<int:pk>/", UnitDetail.as_view(), name="unit-detail"),


     # Customers
    path("api/customers/", CustomerListCreate.as_view(), name="customer-list-create"),
    path("api/customers/<int:pk>/", CustomerDetail.as_view(), name="customer-detail"),

    # rental contract
    path("api/contracts/", RentalContractListCreate.as_view(), name="contract-list-create"),
    path("api/contracts/<int:pk>/", RentalContractDetail.as_view(), name="contract-detail"),
    path("api/contracts/<int:pk>/cancel/", RentalContractCancel.as_view(), name="contract-cancel"),
    path("api/contracts/search/", ContractSearchView.as_view(), name="contract-search"),

    # payrments APIs
    path("api/payments/", PaymentListCreateView.as_view(), name="payment-list-create"),
    path("api/payments/<int:pk>/", PaymentDetailView.as_view(), name="payment-detail"),

    # expenses APIs
    path("api/expenses/", ExpenseListCreateView.as_view(), name="expense-list-create"),
    path("api/expenses/<int:pk>/", ExpenseDetailView.as_view(), name="expense-detail"),

    # maintenance request APIs
    path("api/maintenance-requests/", MaintenanceRequestListCreateView.as_view(), name="maintenance-request-list-create"),
    path("api/maintenance-requests/<int:pk>/", MaintenanceRequestDetailView.as_view(), name="maintenance-request-detail"),


    # General Analytics Endpoint
     path("api/analytics/properties/", PropertyUnitsAnalyticsView.as_view(), name="property-analytics"),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


if settings.DEBUG: 
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)