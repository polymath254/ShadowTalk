
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserProfile

class UserRegisterSerializer(serializers.ModelSerializer):
    public_key = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'public_key')

    def create(self, validated_data):
        public_key = validated_data.pop('public_key')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        user.profile.public_key = public_key
        user.profile.save()
        return user

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()



class UserProfileSerializer(serializers.ModelSerializer):
    public_key = serializers.CharField(source='profile.public_key')

    class Meta:
        model = User
        fields = ('id', 'username', 'public_key')
