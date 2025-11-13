from django.contrib.auth.models import AbstractUser
from django.db import models,IntegrityError,DatabaseError
import uuid
from django.utils import timezone

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    reset_code = models.CharField(max_length=6, blank=True, null=True)
    reset_code_expiry = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.username
    

class Property(models.Model):
    name = models.CharField(max_length=255) 
    address = models.TextField() 
    description = models.TextField(blank=True, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    def __str__(self):
        return self.name
class Unit(models.Model):
    class UnitType(models.TextChoices):
        SINGLE = "single", "Single"
        BEDSITTER = "bedsitter", "Bedsitter"
        STUDIO = "studio", "Studio"
        ONE_BEDROOM = "one_bedroom", "One Bedroom"
        TWO_BEDROOM = "two_bedroom", "Two Bedroom"
        THREE_BEDROOM = "three_bedroom", "Three Bedroom"
        FOUR_BEDROOM = "four_bedroom", "Four Bedroom"
        FIVE_BEDROOM = "five_bedroom", "Five Bedroom"

    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name="units")
    unit_number = models.CharField(max_length=100)
    unit_type = models.CharField(max_length=20, choices=UnitType.choices, default=UnitType.SINGLE)
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=20,
        choices=[("vacant", "Vacant"), ("occupied", "Occupied")],
        default="vacant"
    )
    water_meter_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    electricity_meter_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # 🧾 new fields
    total_billed = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    total_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["property", "unit_number"], name="unique_unit_number_per_property")
        ]

    def __str__(self):
        return f"{self.property.name} - {self.unit_number} ({self.get_unit_type_display()})"

    # 💡 Computed logic
    def recalculate_balance(self):
        """Recalculate billed, paid, and balance for this unit."""
        from django.db.models import Sum

        total_billed = self.contracts.filter(is_active=True)\
            .values_list("receipts__total_amount", flat=True)
        total_billed = sum(total_billed) if total_billed else 0

        total_paid = self.contracts.filter(is_active=True)\
            .values_list("receipts__amount_paid", flat=True)
        total_paid = sum(total_paid) if total_paid else 0

        self.total_billed = total_billed
        self.total_paid = total_paid
        self.balance = total_billed - total_paid  # + means debt, - means overpayment
        self.save(update_fields=["total_billed", "total_paid", "balance"])


# customer details 

def customer_id_upload_path(instance, filename):
    # Store files like: media/customer_ids/<id_number>/<front_or_back>.jpg
    return f"customer_ids/{instance.id_number}/{filename}"

class Customer(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20, unique=True)   # must be unique
    email = models.EmailField(blank=True, null=True, unique=True) # must be unique if given
    id_number = models.CharField(max_length=50, unique=True)      # must be unique
    id_photo_front = models.ImageField(upload_to=customer_id_upload_path, null=True, blank=True)
    id_photo_back = models.ImageField(upload_to=customer_id_upload_path, null=True, blank=True)
    
    # Unit can be assigned later → OneToOne but nullable
    unit = models.OneToOneField(Unit, on_delete=models.SET_NULL, null=True, blank=True, related_name="tenant")
    
    move_in_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.phone_number})"
    


class RentalContract(models.Model):
    contract_number = models.CharField(max_length=50, unique=True, blank=True, null=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="contracts")
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name="contracts")
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    deposit_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    payment_frequency = models.CharField(
        max_length=20,
        choices=[("monthly", "Monthly"), ("quarterly", "Quarterly"), ("yearly", "Yearly")],
        default="monthly"
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.contract_number:
            base_number = f"CTR-{self.customer.id}-{self.unit.id}-{int(self.start_date.strftime('%Y%m%d'))}"
            contract_number = base_number

            # Ensure uniqueness
            counter = 1
            while RentalContract.objects.filter(contract_number=contract_number).exists():
                contract_number = f"{base_number}-{counter}"
                counter += 1

            self.contract_number = contract_number

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.contract_number} → {self.customer} ({self.unit})"


class Payment(models.Model):
    receipt = models.ForeignKey("Receipt", on_delete=models.CASCADE, related_name="payments")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateField(auto_now_add=True)
    method = models.CharField(
        max_length=20,
        choices=[
            ("cash", "Cash"),
            ("mpesa", "M-Pesa"),
            ("bank", "Bank Transfer"),
        ],
        default="cash"
    )
    reference = models.CharField(max_length=100, blank=True, null=True, unique=True)  # Prevent duplicates
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

def save(self, *args, **kwargs):
    super().save(*args, **kwargs)

    # Update receipt totals
    self.receipt.amount_paid += self.amount
    self.receipt.save(update_fields=["amount_paid"])
    self.receipt.update_status()

    # Update unit balance
    unit = self.receipt.contract.unit
    unit.recalculate_balance()



class Expense(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name="expenses")
    description = models.TextField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    expense_date = models.DateField(auto_now_add=True)
    recorded_by = models.ForeignKey("CustomUser", on_delete=models.SET_NULL, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Expense {self.amount} for {self.property.name} ({self.expense_date})"
    



class MaintenanceRequest(models.Model):
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name="maintenance_requests")
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, null=True, blank=True, related_name="requests")
    description = models.TextField()
    status = models.CharField(
        max_length=20,
        choices=[("pending", "Pending"), ("in_progress", "In Progress"), ("resolved", "Resolved")],
        default="pending"
    )
    reported_date = models.DateTimeField(auto_now_add=True)
    resolved_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Request {self.id} - {self.unit} ({self.status})"

class Receipt(models.Model):
    contract = models.ForeignKey(
        "RentalContract",
        on_delete=models.CASCADE,
        related_name="receipts"
    )
    issued_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_receipts"
    )

    STATUS_CHOICES = [
        ('unpaid', 'Unpaid'),
        ('partial', 'Partially Paid'),
        ('paid', 'Fully Paid'),
    ]


    # Core financial fields
    monthly_rent = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    rental_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    electricity_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    electricity_bill = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    water_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    water_bill = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    service_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    security_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    previous_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    other_charges = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Meter readings
    previous_water_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    current_water_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    previous_electricity_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    current_electricity_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Auto-generated fields
    receipt_number = models.CharField(max_length=50, unique=True, editable=False)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='unpaid')
    is_paid = models.BooleanField(default=False)

    issue_date = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        if not self.receipt_number:
            today = timezone.now().strftime("%Y%m%d")
            count = Receipt.objects.filter(contract=self.contract).count() + 1
            self.receipt_number = f"RCT-{self.contract.id}-{today}-{count}"
        super().save(*args, **kwargs)

    @property
    def total_amount(self):
        return (
            self.monthly_rent +
            self.rental_deposit +
            self.electricity_deposit +
            self.electricity_bill +
            self.water_deposit +
            self.water_bill +
            self.service_charge +
            self.security_charge +
            self.previous_balance +
            self.other_charges
        )

    def __str__(self):
        return f"Receipt {self.receipt_number} - Contract {self.contract.contract_number}"

    contract = models.ForeignKey(
        "RentalContract",
        on_delete=models.CASCADE,
        related_name="receipts"
    )
    issued_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_receipts"
    )

    # Core financial fields
    monthly_rent = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    rental_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    electricity_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    electricity_bill = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    water_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    water_bill = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    service_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    security_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    previous_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    other_charges = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Meter readings
    previous_water_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    current_water_reading = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Auto-generated fields
    receipt_number = models.CharField(max_length=50, unique=True, editable=False)
    issue_date = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        # Automatically link unit and property from the contract
        if self.contract:
            self.unit = self.contract.unit
            self.property = self.contract.unit.property

        # If issue_date is not set, default to now
        if not self.issue_date:
            self.issue_date = timezone.now()

        # Generate a unique receipt number based on issue_date (month + year)
        if not self.receipt_number:
            # Use issue_date to extract target year and month
            issue_year = self.issue_date.year
            issue_month = self.issue_date.month
            formatted_month = f"{issue_month:02d}"  # ensure 09 instead of 9

            # Filter receipts of same contract and same year-month
            count = (
                Receipt.objects.filter(
                    contract=self.contract,
                    issue_date__year=issue_year,
                    issue_date__month=issue_month
                ).count() + 1
            )

            # Generate code using the year-month (YYYYMM)
            self.receipt_number = f"RCT-{self.contract.id}-{issue_year}{formatted_month}-{count}"

        # Safety net for unique constraint
        try:
            super().save(*args, **kwargs)
        except IntegrityError:
            count = (
                Receipt.objects.filter(contract=self.contract).count() + 1
            )
            issue_year = self.issue_date.year
            issue_month = self.issue_date.month
            formatted_month = f"{issue_month:02d}"
            self.receipt_number = f"RCT-{self.contract.id}-{issue_year}{formatted_month}-{count}"
            super().save(*args, **kwargs)

        
    def update_status(self):
        """Automatically update payment status and is_paid based on totals."""
        total = self.total_amount

        if self.amount_paid == 0:
            self.status = "unpaid"
            self.is_paid = False
        elif self.amount_paid < total:
            self.status = "partial"
            self.is_paid = False
        else:
            self.status = "paid"
            self.is_paid = True

        self.save(update_fields=["status", "is_paid"])


    @property
    def total_amount(self):
        return sum([
            self.monthly_rent,
            self.rental_deposit,
            self.electricity_deposit,
            self.electricity_bill,
            self.water_deposit,
            self.water_bill,
            self.service_charge,
            self.security_charge,
            self.previous_balance,
            self.other_charges,
        ])

    def __str__(self):
        return f"Receipt {self.receipt_number} - Contract {self.contract.contract_number}"



# ######system params

class SystemParameter(models.Model):
    property = models.OneToOneField(
        Property,
        on_delete=models.CASCADE,
        related_name="system_parameters"
    )

    #  Bill inclusions
    has_water_bill = models.BooleanField(default=True)
    has_electricity_bill = models.BooleanField(default=True)
    has_service_charge = models.BooleanField(default=True)
    has_security_charge = models.BooleanField(default=False)
    has_other_charges = models.BooleanField(default=False)

    #  Deposit configuration
    rent_deposit_months = models.PositiveIntegerField(default=1)
    require_water_deposit = models.BooleanField(default=False)
    require_electricity_deposit = models.BooleanField(default=False)

    #  Optional settings
    allow_partial_payments = models.BooleanField(default=True)
    auto_generate_receipts = models.BooleanField(default=False)
    late_payment_penalty_rate = models.DecimalField(
        max_digits=5, decimal_places=2, default=0.00,
        help_text="Percentage penalty for late rent (e.g., 2.5 means 2.5%)"
    )
    grace_period_days = models.PositiveIntegerField(default=5)

    #  Default fees (optional)
    default_service_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    default_security_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    default_other_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    electicity_unit_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    water_unit_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"System Params for {self.property.name}"
