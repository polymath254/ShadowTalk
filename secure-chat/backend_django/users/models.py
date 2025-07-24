from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    public_key = models.TextField()  # Store PEM/BASE64 encoded public key
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    pair_token = models.CharField(max_length=64, null=True, blank=True)
    def __str__(self):
        return f"{self.user.username} Profile"

