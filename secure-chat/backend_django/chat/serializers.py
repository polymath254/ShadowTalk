
from rest_framework import serializers
from .models import EncryptedMessage
from .models import Group, GroupMember, GroupMessage

class EncryptedMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptedMessage
        fields = ('id', 'sender', 'recipient', 'ciphertext', 'attachment', 'filename', 'mime_type', 'timestamp','burn_after_read','expiry_seconds','sender_hash', 'recipient_hash', 'delivered','recipient_hash')
        read_only_fields = ('id', 'timestamp', 'sender')

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'

class GroupMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMember
        fields = '__all__'

class GroupMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMessage
        fields = '__all__'        