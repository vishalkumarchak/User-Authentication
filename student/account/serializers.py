from account.models import User
from rest_framework import serializers
from xml.dom import ValidationErr
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode 
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import Util



class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 =serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model=User
        fields = ['email', 'name', 'password', 'password2','tc']
        extra_kwargs={'password':{'write_only': True}}

# Validating password and confirm password while Registration
def validate(self, attrs):                  #attrs ya data same word h
    password = attrs.get('password')
    password2 = attrs.get('password2')
    if password != password2:
        raise serializers.ValidationError("Password and Password2 doesn't match")
    return attrs

def create (self, validate_data):
    return User.objects.create(**validate_data) 

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields= ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields =['id', 'email', 'name']

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password', 'password2']
    
    def validate(self, attrs):   
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
          raise serializers.ValidationError("Password and Password2 doesn't match")
        user.set_password(password)
        user.save()
        return attrs
        
class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = 'http//localhost:8000/api/reset/'+uid+'/'+token
            # print( 'Password Reset Link',link)
            #send Email
            body = 'Click Following Link to Reset your Password'+link
            data={
                'subject' :'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationErr('You are not a Registered User')
        
class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password', 'password2']
        
    def validate(self, attrs):   
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
               raise serializers.ValidationError("Password and Confirm_Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationErr('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationErr('Token is not Valid or Expired')

        