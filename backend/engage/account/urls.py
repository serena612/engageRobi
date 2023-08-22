from django.shortcuts import render
from django.urls import path, include, reverse_lazy
from rest_framework.routers import SimpleRouter
from django.contrib.auth.decorators import login_required
from . import api, views
from django.contrib.auth import views as auth_views
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
# from django.contrib.auth.views import PasswordChangeView
# from django.core.exceptions import ValidationError
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.utils.translation import ugettext_lazy as _
from django.views.generic import RedirectView

def CustomPasswordChangeView(request):
    form = PasswordChangeForm(user=request.user)
    if not 'tms' in request.COOKIES: # hasattr(request.session, 'tms'): # 
        tms = 0 
    else:
        tms = int(request.COOKIES.get('tms')) # request.session['tms']
    if request.method == 'POST':
        
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            messages.success(request, _('Password changed successfully.'))
            form.save()
            tms = 0
            update_session_auth_hash(request, form.user)
        elif 'old_password' in form.errors:
            # print("found wrong old password !!")
            tms += 1
            if tms>= 5:
                request.session.flush()
                
                taka = redirect('password_change')
                logout(request)
                # request.session['tms'] = 0
                taka.set_cookie("tms",0)
                messages.warning(request, _('You entered your old password incorrectly multiple times! Please log in again to continue.'))
                return taka
        
            
        # print("Detected", str(tms), "times !!")
    taka = render(request, 'registration/password_change_form.html', {
    'form': form, 'site_title':'Engage', 'title':'Password Change', 'site_header':'Engage'
    })
    
    taka.set_cookie("tms",tms)
    return taka 


router = SimpleRouter()
router.register('friends', api.FriendViewSet)
router.register('fcm', api.FCMViewSet, 'fcm')
router.register('users', api.UserViewSet)
router.register('auth', api.AuthViewSet, 'auth')


urlpatterns = [
    path('api/', include(router.urls)),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/logout2/', views.logout2_view, name='logout3'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/<uuid:uid>', views.public_profile_view, name='public-profile'),
    path('profile/set-game-account/', views.set_game_linked_account,name='set-game-account'),
    path('prizes/', views.prizes_view, name='prizes'),
    path('winners/', views.winners_view, name='winners'),
    path('admin/logout/', auth_views.LogoutView.as_view(
    next_page=reverse_lazy('admin:login') # you can use your named URL here just like you use the **url** tag in your django template
    ), name='logout2'),
    path('admin/password_change/', login_required(CustomPasswordChangeView),name='password_change'),
    path('accounts/login/', RedirectView.as_view(url='/')),
]
