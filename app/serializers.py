from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .models import Expense, MaintenanceRequest, Payment, Property, Receipt, RentalContract, Unit,Customer



User = get_user_model()


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
        user.is_active = False  # User must verify email to activate account
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
        user = None

        # Try username
        user = authenticate(username=identifier, password=password)

        if not user:
            # Try email
            try:
                user_obj = User.objects.get(email=identifier)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                pass

        if not user:
            # Try phone
            try:
                user_obj = User.objects.get(phone_number=identifier)
                user = authenticate(username=user_obj.username, password=password)
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
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    reset_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs
    
class PasswordResetCodeCheckSerializer(serializers.Serializer):
    email = serializers.EmailField()
    reset_code = serializers.CharField(max_length=6)

class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = "__all__"

class UnitSerializer(serializers.ModelSerializer):

    property_name = serializers.CharField(source="property.name", read_only=True)

    class Meta:
        model = Unit
        fields = "__all__"

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = "__all__"

class RentalContractSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source="customer.first_name", read_only=True)
    customer_phone = serializers.CharField(source="customer.phone_number", read_only=True)
    unit_info = serializers.CharField(source="unit.unit_number", read_only=True)

    class Meta:
        model = RentalContract
        fields = "__all__"

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = "__all__"

class ExpenseSerializer(serializers.ModelSerializer):
    property_name = serializers.CharField(source="property.name", read_only=True)
    recorded_by_name = serializers.CharField(source="recorded_by.username", read_only=True)

    class Meta:
        model = Expense
        fields = [
            "id",
            "property",
            "property_name",
            "description",
            "amount",
            "expense_date",
            "recorded_by",
            "recorded_by_name",
            "created_at",
            "updated_at",
        ]

class MaintenanceRequestSerializer(serializers.ModelSerializer):

    unit_name = serializers.CharField(source="unit.name", read_only=True)
    customer_name = serializers.CharField(source="customer.name", read_only=True)

    class Meta:
        model = MaintenanceRequest
        fields = [
            "id",
            "unit",
            "unit_name",
            "customer",
            "customer_name",
            "description",
            "status",
            "reported_date",
            "resolved_date",
        ]
        read_only_fields = ["reported_date", "resolved_date"]

class ReceiptSerializer(serializers.ModelSerializer):
    total_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, read_only=True
    )
    contract_number = serializers.CharField(
        source="contract.contract_number", read_only=True
    )

    class Meta:
        model = Receipt
        fields = [
            "id",
            "receipt_number",
            "contract",
            "contract_number",
            "issued_by",
            "issue_date",
            "monthly_rent",
            "rental_deposit",
            "electricity_deposit",
            "electricity_bill",
            "water_deposit",
            "water_bill",
            "service_charge",
            "security_charge",
            "previous_balance",
            "other_charges",
            "previous_water_reading",
            "current_water_reading",
            "total_amount",
        ]
        read_only_fields = ["receipt_number", "issue_date", "total_amount", "issued_by"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["issued_by"] = request.user

        # create the receipt
        receipt = super().create(validated_data)

        # update the linked Unit readings
        unit = receipt.contract.unit
        if receipt.current_water_reading is not None:
            unit.water_meter_reading = receipt.current_water_reading

        if receipt.electricity_meter_reading is not None:
            unit.electricity_meter_reading = receipt.electricity_meter_reading

        # ⚡ If you want to support electricity later,
        # add current_electricity_reading field in Receipt
        # and then update unit.electricity_meter_reading here

        unit.save(update_fields=["water_meter_reading", "electricity_meter_reading"])

        return receipt
