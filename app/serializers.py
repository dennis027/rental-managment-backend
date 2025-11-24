from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .models import (
    Property, Unit, Customer, RentalContract,
    Receipt, Payment, Expense, MaintenanceRequest,
    SystemParameter, Expense, Payment, Receipt, Customer
)

User = get_user_model()

# =================================================================
# ---------------------- AUTH SERIALIZERS -------------------------
# =================================================================

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    confirm_password = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ("username", "email", "phone_number", "password", "confirm_password")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email"),
            phone_number=validated_data.get("phone_number"),
            password=validated_data["password"],
        )
        user.is_active = False
        user.save()
        return user


class ResendActivationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
            if user.is_active:
                raise serializers.ValidationError("This account is already activated.")
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email address.")


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        identifier = data.get("identifier")
        password = data.get("password")

        user = authenticate(username=identifier, password=password)

        if not user:
            # Try email
            try:
                u = User.objects.get(email=identifier)
                user = authenticate(username=u.username, password=password)
            except User.DoesNotExist:
                pass

        if not user:
            # Try phone
            try:
                u = User.objects.get(phone_number=identifier)
                user = authenticate(username=u.username, password=password)
            except User.DoesNotExist:
                pass

        if not user:
            raise serializers.ValidationError("Invalid credentials")

        data["user"] = user
        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No account found with this email.")
        return value


class PasswordResetCodeCheckSerializer(serializers.Serializer):
    email = serializers.EmailField()
    reset_code = serializers.CharField(max_length=6)


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    reset_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs


# =================================================================
# ------------------ PROPERTY & UNIT SERIALIZERS -----------------
# =================================================================

class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = "__all__"


class UnitSerializer(serializers.ModelSerializer):
    property_name = serializers.CharField(source='property.name', read_only=True)
    unit_type_display = serializers.CharField(source='get_unit_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    tenant_name = serializers.SerializerMethodField()
    active_contract_deposit = serializers.SerializerMethodField()

    # 🔥 Add these two
    contract_id = serializers.SerializerMethodField()
    contract_number = serializers.SerializerMethodField()

    class Meta:
        model = Unit
        fields = "__all__"  # your existing fields
        # DRF will automatically append the two new fields

    def get_tenant_name(self, obj):
        if hasattr(obj, "tenant") and obj.tenant:
            return f"{obj.tenant.first_name} {obj.tenant.last_name}"
        return None

    def get_active_contract_deposit(self, unit):
        contract = unit.contracts.filter(is_active=True).first()
        return contract.deposit_amount if contract else 0

    # -------------- 🔥 NEW METHODS -------------------

    def get_contract_id(self, unit):
        """Return active contract ID or None."""
        contract = unit.contracts.filter(is_active=True).first()
        return contract.id if contract else None

    def get_contract_number(self, unit):
        """Return active contract number or None."""
        contract = unit.contracts.filter(is_active=True).first()
        return contract.contract_number if contract else None



# =================================================================
# ---------------------- CUSTOMER SERIALIZER ----------------------
# =================================================================

class CustomerSerializer(serializers.ModelSerializer):
    unit_number = serializers.CharField(source="unit.unit_number", read_only=True)
    property_name = serializers.CharField(source="unit.property.name", read_only=True)

    class Meta:
        model = Customer
        fields = "__all__"


# =================================================================
# ---------------------- RENTAL CONTRACT ---------------------------
# =================================================================

class RentalContractSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()
    customer_phone = serializers.CharField(source="customer.phone_number", read_only=True)
    unit_number = serializers.CharField(source="unit.unit_number", read_only=True)
    property_name = serializers.CharField(source="unit.property.name", read_only=True)

    class Meta:
        model = RentalContract
        fields = "__all__"

    def get_customer_name(self, obj):
        return f"{obj.customer.first_name} {obj.customer.last_name}" if obj.customer else None


# =================================================================
# ----------------------- RECEIPT SERIALIZER ----------------------
# =================================================================

class ReceiptSerializer(serializers.ModelSerializer):
    contract_number = serializers.CharField(source="contract.contract_number", read_only=True)
    customer = serializers.CharField(source="contract.customer.first_name", read_only=True)
    unit = serializers.CharField(source="contract.unit.unit_number", read_only=True)
    property = serializers.CharField(source="contract.unit.property.name", read_only=True)
    property_id = serializers.CharField(source="contract.unit.property.id", read_only=True)
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    balance = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = Receipt
        fields = "__all__"
        read_only_fields = ["receipt_number", "issue_date", "total_amount", "issued_by"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["issued_by"] = request.user

        receipt = super().create(validated_data)

        # Update meter readings
        unit = receipt.contract.unit
        if receipt.current_water_reading is not None:
            unit.water_meter_reading = receipt.current_water_reading
        if receipt.current_electricity_reading is not None:
            unit.electricity_meter_reading = receipt.current_electricity_reading
        unit.save()

        return receipt


# =================================================================
# ------------------------ PAYMENT SERIALIZER ---------------------
# =================================================================

class PaymentSerializer(serializers.ModelSerializer):
    receipt_number = serializers.CharField(source="receipt.receipt_number", read_only=True)
    method_display = serializers.CharField(source="get_method_display", read_only=True)
    customer_name = serializers.SerializerMethodField()
    property_id = serializers.SerializerMethodField()
    unit_id = serializers.SerializerMethodField()
    unit_name = serializers.SerializerMethodField()

    class Meta:
        model = Payment
        fields = "__all__"

    def get_customer_name(self, obj):
        if obj.receipt and obj.receipt.contract.customer:
            return f"{obj.receipt.contract.customer.first_name} {obj.receipt.contract.customer.last_name}"
        return None

    def get_property_id(self, obj):
        if obj.receipt and obj.receipt.contract.unit:
            return obj.receipt.contract.unit.property.id
        elif obj.expense and obj.expense.property:
            return obj.expense.property.id
        elif obj.maintenance_request and obj.maintenance_request.unit:
            return obj.maintenance_request.unit.property.id
        return None



    def get_unit_id(self, obj):
        if obj.receipt and obj.receipt.contract.unit:
            return obj.receipt.contract.unit.id
        return None

    def get_unit_name(self, obj):
        if obj.receipt and obj.receipt.contract.unit:
            return obj.receipt.contract.unit.unit_number
        return None


# =================================================================
# ------------------------ EXPENSE SERIALIZER ---------------------
# =================================================================

class ExpenseSerializer(serializers.ModelSerializer):
    property_name = serializers.CharField(source="property.name", read_only=True)
    recorded_by_username = serializers.CharField(source="recorded_by.username", read_only=True)

    class Meta:
        model = Expense
        fields = "__all__"


# =================================================================
# ------------------ MAINTENANCE REQUEST SERIALIZER ---------------
# =================================================================

class MaintenanceRequestSerializer(serializers.ModelSerializer):
    unit_number = serializers.CharField(source='unit.unit_number', read_only=True)
    property_name = serializers.CharField(source='unit.property.name', read_only=True)
    property_id = serializers.IntegerField(source='unit.property.id', read_only=True)
    customer_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = MaintenanceRequest
        fields = "__all__"

    def get_customer_name(self, obj):
        if obj.customer:
            return f"{obj.customer.first_name} {obj.customer.last_name}"
        return None

# =================================================================
# ------------------- SYSTEM PARAMETERS SERIALIZER ----------------
# =================================================================

class SystemParameterSerializer(serializers.ModelSerializer):
    property_name = serializers.CharField(source="property.name", read_only=True)

    class Meta:
        model = SystemParameter
        fields = "__all__"
        read_only_fields = ["created_at", "updated_at"]


# =================================================================
# ---------------------- REPORT SERIALIZERS -----------------------
# =================================================================

class RevenueSummarySerializer(serializers.Serializer):
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    revenue_by_property = serializers.ListField()
    revenue_by_method = serializers.ListField()


class OccupancySummarySerializer(serializers.Serializer):
    total_units = serializers.IntegerField()
    occupied = serializers.IntegerField()
    vacant = serializers.IntegerField()
    occupancy_rate = serializers.FloatField()


class FinancialSummarySerializer(serializers.Serializer):
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    total_expenses = serializers.DecimalField(max_digits=12, decimal_places=2)
    net_profit = serializers.DecimalField(max_digits=12, decimal_places=2)
    profit_margin = serializers.FloatField()
    outstanding_balances = serializers.DecimalField(max_digits=12, decimal_places=2)


class TenantSummarySerializer(serializers.Serializer):
    tenant_name = serializers.CharField()
    phone_number = serializers.CharField()
    unit_number = serializers.CharField()
    property_name = serializers.CharField()
    balance = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_paid = serializers.DecimalField(max_digits=10, decimal_places=2)
