from django.contrib.auth.models import AbstractUser
from django.db import models

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
    unit_type = models.CharField(
        max_length=20,
        choices=UnitType.choices,
        default=UnitType.SINGLE
    )
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=20,
        choices=[("vacant", "Vacant"), ("occupied", "Occupied")],
        default="vacant"
    )
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.property.name} - {self.unit_number} ({self.get_unit_type_display()})"




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

    def __str__(self):
        return f"Contract: {self.customer} → {self.unit} ({self.start_date})"
