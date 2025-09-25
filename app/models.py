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
