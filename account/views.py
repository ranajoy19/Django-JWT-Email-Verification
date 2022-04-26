from .serializer import UserRegistrationSerializer, UserLoginSerializer, \
    UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,\
    UserPasswordResetSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import CustomUser
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from .renderers import UserRenderer
from rest_framework import status


# Create your views here.

# Creating tokens manually

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request ):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user =serializer.save()
            token = get_tokens_for_user(user)
            return Response({'payload':serializer.data, 'message': 'your successfully registered','Token':token},
                            status=status.HTTP_201_CREATED)
        return Response({'payload': serializer.errors, 'status': status.HTTP_400_BAD_REQUEST})


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'payload':serializer.data,'message': 'your logged in Successfully','Token':token},
                                status=status.HTTP_201_CREATED)
            else:
                return Response({'Errors': {'non_field_error': ['Email or PASSWORD is not Valid']}},
                                status=status.HTTP_404_NOT_FOUND)
        return Response({'error':serializer.errors},
                        status=status.HTTP_201_CREATED)


class UserProfileView(APIView):
    permission_classes = (IsAuthenticated,)
    renderer_classes = [UserRenderer]

    def get(self,request):

        #user = CustomUser.objects.all()
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    permission_classes = (IsAuthenticated,)
    renderer_classes = [UserRenderer]
    def post(self,request):
        serializer =UserChangePasswordSerializer(data =request.data,
                                                 context={'user':request.user})
        if serializer.is_valid():

            return Response({'payload':serializer.data,
                             'message':'your have successfully change your password'},
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    def post(self,request):
        serializer =SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'payload': serializer.data,
                             'message': 'Password reset link Send to your email,Please Check '},
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self,request,uid,token):
        serializer = UserPasswordResetSerializer(data =request.data,context={'uid':uid,'token':token})
        if serializer.is_valid():
            return Response({
                             'message': 'Password Reset Successfully '},
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



