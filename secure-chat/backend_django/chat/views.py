from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import EncryptedMessage
from .serializers import EncryptedMessageSerializer
from django.contrib.auth.models import User
import requests
import os
from .models import Group, GroupMember
from .models import Group, GroupMember, GroupMessage
from .serializers import GroupSerializer, GroupMemberSerializer, GroupMessageSerializer

SOCKET_SERVER_URL = os.getenv('SOCKET_SERVER_URL', 'http://localhost:5000')

class SendMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        recipient_id = data.get('recipient')
        ciphertext = data.get('ciphertext')
        attachment = data.get('attachment', None)
        filename = data.get('filename', None)
        mime_type = data.get('mime_type', None)

        try:
            recipient = User.objects.get(id=recipient_id)
        except User.DoesNotExist:
            return Response({'error': 'Recipient not found.'}, status=status.HTTP_404_NOT_FOUND)

        message = EncryptedMessage.objects.create(
            sender=request.user,
            recipient=recipient,
            ciphertext=ciphertext,
            attachment=attachment,
            filename=filename,
            mime_type=mime_type
        )
        serializer = EncryptedMessageSerializer(message)
        
        # --- Notify real-time server about new message ---
        try:
            notify_payload = {'recipient_id': recipient.id}
            requests.post(f"{SOCKET_SERVER_URL}/notify", json=notify_payload, timeout=2)
        except Exception as e:
            # Log, don't fail on notification
            print(f"Socket notification failed: {e}")
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class ReceiveMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
     messages = EncryptedMessage.objects.filter(recipient=request.user, delivered=False)
     expired_ids = [m.id for m in messages if m.is_expired()]
     EncryptedMessage.objects.filter(id__in=expired_ids).delete()

     messages = messages.exclude(id__in=expired_ids)
     serializer = EncryptedMessageSerializer(messages, many=True)
     # Mark as delivered and delete if burn_after_read
     messages.delete()
     burn_ids = [m.id for m in messages if m.burn_after_read]
     EncryptedMessage.objects.filter(id__in=burn_ids).delete()
     messages.filter(id__in=burn_ids).update(delivered=True)
     
     return Response(serializer.data)

class CreateGroupView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        name = request.data.get('name')
        members = request.data.get('members')  # List of usernames
        encrypted_keys = request.data.get('encrypted_keys')  # Dict username->encrypted_group_key

        if not name or not members or not encrypted_keys:
            return Response({'error': 'Missing fields'}, status=400)

        group = Group.objects.create(name=name, creator=request.user)
        for username in members:
            try:
                user = User.objects.get(username=username)
                GroupMember.objects.create(
                    group=group,
                    user=user,
                    encrypted_group_key=encrypted_keys[username]
                )
            except User.DoesNotExist:
                continue

        return Response(GroupSerializer(group).data, status=201)

class ListGroupsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        groups = Group.objects.filter(members__user=request.user)
        return Response(GroupSerializer(groups, many=True).data)
    
class RotateGroupKeyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, group_id):
        group = Group.objects.get(id=group_id)
        # Only allow group creator/admin to rotate
        if group.creator != request.user:
            return Response({'error': 'Not authorized'}, status=403)

        encrypted_keys = request.data.get('encrypted_keys')  # dict: username -> new encrypted_group_key
        updated = 0
        for m in group.members.all():
            key = encrypted_keys.get(m.user.username)
            if key:
                m.encrypted_group_key = key
                m.save()
                updated += 1
        return Response({'ok': True, 'updated': updated})