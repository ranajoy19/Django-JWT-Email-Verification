from django.urls import path
from account.views import UserRegistrationView,UserLoginView,UserProfileView,\
    UserChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView

urlpatterns = [
    path('register',UserRegistrationView.as_view(),name ='register'),
    path('login',UserLoginView.as_view(),name ='login'),
    path('profile',UserProfileView.as_view(),name ='profile'),
    path('change_password',UserChangePasswordView.as_view(),name ='change_password'),
    path('send_password_reset_email',SendPasswordResetEmailView.as_view(),
         name ='send_password_reset_email'),
    path('reset-password/<str:uid>/<str:token>/',UserPasswordResetView.as_view(),name='reset-password')
]
