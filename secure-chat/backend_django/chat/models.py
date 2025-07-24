from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import hashlib

def hash_username(username):
    return hashlib.sha256(username.encode()).hexdigest()

class EncryptedMessage(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    ciphertext = models.BinaryField()  # Encrypted message payload (text or metadata+text)
    attachment = models.BinaryField(null=True, blank=True)  # Encrypted image/file bytes
    timestamp = models.DateTimeField(auto_now_add=True)
    delivered = models.BooleanField(default=False)
    filename = models.CharField(max_length=255, null=True, blank=True)
    mime_type = models.CharField(max_length=50, null=True, blank=True)
    burn_after_read = models.BooleanField(default=False)
    expiry_seconds = models.IntegerField(null=True, blank=True)
    sender_hash = models.CharField(max_length=64, db_index=True, blank=True)
    recipient_hash = models.CharField(max_length=64, db_index=True, blank=True)
    # No plaintext, no subject, no metadata: privacy by default
    def save(self, *args, **kwargs):
        if self.sender and not self.sender_hash:
            self.sender_hash = hash_username(self.sender.username)
        if self.recipient and not self.recipient_hash:
            self.recipient_hash = hash_username(self.recipient.username)
        super().save(*args, **kwargs)

    def is_expired(self):
        if self.expiry_seconds:
            return timezone.now() > self.timestamp + timedelta(seconds=self.expiry_seconds)
        return False
    def __str__(self):
        return f"From {self.sender.username} to {self.recipient.username} at {self.timestamp}"

class Group(models.Model):
    name = models.CharField(max_length=80)
    creator = models.ForeignKey(User, related_name="created_groups", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class GroupMember(models.Model):
    group = models.ForeignKey(Group, related_name="members", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="group_memberships", on_delete=models.CASCADE)
    encrypted_group_key = models.TextField()  # Encrypted with member's public key
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("group", "user")

class GroupMessage(models.Model):
    group = models.ForeignKey(Group, related_name="messages", on_delete=models.CASCADE)
    sender = models.ForeignKey(User, related_name="group_messages", on_delete=models.CASCADE)
    ciphertext = models.TextField()
    attachment = models.TextField(blank=True, null=True)
    filename = models.CharField(max_length=255, blank=True, null=True)
    mime_type = models.CharField(max_length=64, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    burn_after_read = models.BooleanField(default=False)
    expiry_seconds = models.IntegerField(null=True, blank=True)