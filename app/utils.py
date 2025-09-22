from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


def generate_activation_link(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    domain = request.get_host()
    return f"http://{domain}/api/activate/{uid}/{token}/"

def generate_password_reset_link(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    domain = request.get_host()
    return f"http://{domain}/api/reset-password-confirm/{uid}/{token}/"


