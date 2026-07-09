from django.contrib import admin
from .models import (
    CustomUser,
    Property,
    Unit,
    Customer,
    RentalContract,
    Receipt,
    Payment,
    Expense,
    MaintenanceRequest,
    SystemParameter,
)

admin.site.register(CustomUser)
admin.site.register(Property)
admin.site.register(Unit)
admin.site.register(Customer)
admin.site.register(RentalContract)
admin.site.register(Receipt)
admin.site.register(Payment)
admin.site.register(Expense)
admin.site.register(MaintenanceRequest)
admin.site.register(SystemParameter)