from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import ActivateAccountView, ContractSearchView, CustomerDetail, CustomerListCreate, ExpenseDetailView, ExpenseListCreateView, GenerateMonthlyReceiptsView, MaintenanceRequestDetailView, MaintenanceRequestListCreateView, PaymentDetailView, PaymentListCreateView, PropertySystemParameterView, PropertyUnitsAnalyticsView, PropertyDetail, PropertyListCreate, ReceiptDetailView, ReceiptListCreateView, RegisterView, LoginView,PasswordResetRequestView,PasswordResetConfirmView,PasswordResetCodeCheckView,LogoutView, RentalContractCancel, RentalContractDetail, RentalContractListCreate,ResendActivationWithRateLimitView, UnitDetail, UnitListCreate 

from django.conf import settings
from django.conf.urls.static import static

from app import views

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

    # Receipt APIs
    path("api/receipts/", ReceiptListCreateView.as_view(), name="receipt-list-create"),
    path("api/receipts/<int:pk>/", ReceiptDetailView.as_view(), name="receipt-detail"),
    path('api/receipts/generate-monthly-receipts/', GenerateMonthlyReceiptsView.as_view(), name='generate-receipts'),


    # General Analytics Endpoint
     path("api/analytics/properties/", PropertyUnitsAnalyticsView.as_view(), name="property-analytics"),


     path("api/properties/<int:property_id>/system-parameters/", PropertySystemParameterView.as_view(), name="property-system-parameters"),


         # Dashboard APIs
    path('api/dashboard/summary/', views.dashboard_summary, name='dashboard-summary'),
    path('api/dashboard/monthly-collection/', views.monthly_rent_collection, name='monthly-collection'),
    path('api/dashboard/occupancy/', views.occupancy_stats, name='occupancy-stats'),
    path('api/dashboard/payment-methods/', views.payment_methods_breakdown, name='payment-methods'),
    path('api/dashboard/revenue-expenses/', views.revenue_vs_expenses, name='revenue-expenses'),
    

        # Financial Reports
    path('api/revenue/total/', views.TotalRevenueReportView.as_view(), name='revenue-total'),
    path('api/balances/outstanding/', views.OutstandingBalancesReportView.as_view(), name='balances-outstanding'),
    path('api/payments/collections/', views.PaymentCollectionReportView.as_view(), name='payments-collections'),
    path('api/rent-roll/', views.RentRollReportView.as_view(), name='rent-roll'),
    path('api/deposits/tracking/', views.DepositTrackingReportView.as_view(), name='deposits-tracking'),
    path('api/expenses/analysis/', views.ExpenseAnalysisReportView.as_view(), name='expenses-analysis'),
    path('api/profit-loss/', views.ProfitLossReportView.as_view(), name='profit-loss'),
    path('api/defaulters/', views.DefaultersReportView.as_view(), name='defaulters'),
    path('api/payments/methods/', views.PaymentMethodAnalysisView.as_view(), name='payment-methods'),
    path('api/revenue/forecast/', views.RevenueForecastReportView.as_view(), name='revenue-forecast'),
    
    # Occupancy & Unit Reports
    path('api/occupancy/rate/', views.OccupancyRateReportView.as_view(), name='occupancy-rate'),
    path('api/units/performance/', views.UnitPerformanceReportView.as_view(), name='units-performance'),
    path('api/vacancy/duration/', views.VacancyDurationReportView.as_view(), name='vacancy-duration'),
    path('api/units/type-analysis/', views.UnitTypeAnalysisView.as_view(), name='units-type-analysis'),
    path('api/tenant-movement/', views.TenantMovementReportView.as_view(), name='tenant-movement'),
    path('api/rent/pricing/', views.RentPricingAnalysisView.as_view(), name='rent-pricing'),
    path('api/units/utilization/', views.UnitUtilizationReportView.as_view(), name='units-utilization'),
    path('api/units/available/', views.AvailableUnitsReportView.as_view(), name='units-available'),
    
    # Tenant & Customer Reports
    path('api/tenants/directory/', views.TenantDirectoryReportView.as_view(), name='tenants-directory'),
    path('api/tenants/<int:tenant_id>/payment-history/', views.TenantPaymentHistoryView.as_view(), name='tenant-payment-history'),
    path('api/tenants/arrears-aging/', views.TenantArrearsAgingView.as_view(), name='tenants-arrears-aging'),
    path('api/contracts/expiring/', views.ContractExpiryReportView.as_view(), name='contracts-expiring'),
    path('api/tenants/new/', views.NewTenantReportView.as_view(), name='tenants-new'),
    path('api/tenants/retention/', views.TenantRetentionReportView.as_view(), name='tenants-retention'),
    
    # Utility & Maintenance Reports
    path('api/utilities/consumption/', views.UtilityConsumptionReportView.as_view(), name='utilities-consumption'),
    path('api/utilities/revenue/', views.UtilityRevenueReportView.as_view(), name='utilities-revenue'),
    path('api/maintenance/requests/', views.MaintenanceRequestReportView.as_view(), name='maintenance-requests'),
    path('api/maintenance/costs/', views.MaintenanceCostReportView.as_view(), name='maintenance-costs'),
    
    # Executive & Dashboard Reports
    path('api/dashboard/executive/', views.ExecutiveDashboardView.as_view(), name='dashboard-executive'),
    path('api/properties/comparison/', views.PropertyComparisonReportView.as_view(), name='properties-comparison'),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


if settings.DEBUG: 
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)