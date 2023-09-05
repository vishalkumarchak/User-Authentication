from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from account.serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .models import User


# Create your views here.

# Generate Token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
      #  'refresh': str(refresh),
       'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
   renderer_classes = [UserRenderer]
   def post(self, request, format=None):
      serializer = UserRegistrationSerializer(data=request.data)
      serializer.is_valid(raise_exception=True)
      user= serializer.save()
      token = get_tokens_for_user(user)
      responce={'Code':status.HTTP_400_BAD_REQUEST,'Status':'success',
       'Message':'Registration Successfully','data':serializer.errors,'token':token}
      return Response(responce,status=status.HTTP_200_OK)
   
class UserLoginView(APIView):
   renderer_classes = [UserRenderer]
   def post(self,request, format=None):
      serializer = UserLoginSerializer(data=request.data)
      serializer.is_valid(raise_exception=True)
      email = serializer.data.get('email')
      password = serializer.data.get('password')
      user = authenticate(email=email, password=password)
      if user is not None:
         token = get_tokens_for_user(user)
         responce={'Code':status.HTTP_200_OK,'Status':'Success',
                  'Message':'Login Successfully','Data':serializer.data,'token':token}
         return Response(responce,status=status.HTTP_200_OK)
      else:
            responce={'Code':status.HTTP_404_NOT_FOUND,'Status':'unsuccess',
                     'Message':'Credentials Wrong, Please Check the Username and Password'}
            return Response(responce,status=status.HTTP_404_NOT_FOUND)
         
      
   
class UserProfileView(APIView):
   renderer_classes = [UserRenderer]
   permission_classes = [IsAuthenticated]
   def get(self, request, format=None):
      serializer = UserProfileSerializer(request.user)
      responce={'code':status.HTTP_200_OK,'status':'success','message':'profile sucesssfully fetched','data':serializer.data}
      return Response(responce,status=status.HTTP_200_OK)
   
   
class UserChangePasswordView(APIView):
   renderer_classes = [UserRenderer]
   permission_classes = [IsAuthenticated]
   def post(self, request, format=None):
      serializer = UserChangePasswordSerializer(data=request.data, context= {'user':request.user})
      serializer.is_valid(raise_exception=True)
      return Response({'Message': 'Password Changed Successfully'},status=status.HTTP_200_OK)
      
      
      
class SendPasswordResetEmailView(APIView):
   renderer_classes = [UserRenderer]
   def post(self, request, format=None):
      serializer =SendPasswordResetEmailSerializer(data=request.data)
      serializer.is_valid(raise_exception=True)
      responce={'Code':status.HTTP_200_OK,'Status':'Password Reset Link Send your Email.','Message':' Please check your Email.','data':serializer.data}
      return Response(responce,status=status.HTTP_200_OK)
   
      
class UserPasswordResetView(APIView):
   renderer_classes = [UserRenderer]
   def post(self, request,uid, token, format=None):
      serializer = UserPasswordResetSerializer(data=request.data,context = {'uid':uid, 'token':token})
      serializer.is_valid(raise_exception=True)
      responce={'Code':status.HTTP_200_OK,'Status':'Success','Message':'Password Reset Successfully.'}
      return Response(responce,status=status.HTTP_200_OK)
      