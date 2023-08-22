from datetime import datetime, timedelta, date
from django.shortcuts import redirect
from engage.settings.base import PASS_EXPIRE_DAYS, CUSTOM_COOKIE_AGE, CUSTOM_COOKIE_RENEW
from django_password_validators.password_history.models import (
    PasswordHistory,
    UserPasswordHistoryConfig,
)
from django.contrib import messages

class AccountExpiry:

    def __init__(self, get_response):
        self.get_response = get_response


    def get_last_timestamp(self, user):
        
        # find timestamp to last used password
        password_ids = list(
            PasswordHistory.objects. \
                filter(user_config__user=user). \
                order_by('-date')[:1]. \
                values_list('date', flat=True)
        )
        if password_ids:
            return password_ids[0].date()
        else:
            return date(2070,1,1)  # a user with no password history won't be requested to change (old users)


    def __call__(self, request):
        
        # print(request.is_secure())
        if not request.is_secure():
            request.session['headeren'] = str(request.headers)
            if 'msisdn' in request.headers:
                request.session['msisdn'] = request.headers['msisdn']
            if 'headers' not in request.path:
                gaga = request.build_absolute_uri().replace('http', 'https')
                # return redirect(gaga)  # this forces http to https redirection, do not enable on local, just on deployment
        elif 'headeren' in request.session:
            print(request.session['headeren'])
        current_user = request.user
        response = self.get_response(request)
        if current_user.is_staff:
            if request.session.get_expiry_age()>int(CUSTOM_COOKIE_AGE):
                request.session.set_expiry(int(CUSTOM_COOKIE_AGE))
            if CUSTOM_COOKIE_RENEW:
                request.session.set_expiry(int(CUSTOM_COOKIE_AGE))
        # expiry_path = reverse('accounts:account-expired')
        if '/admin/password_change/' not in request.path:
            if current_user.is_anonymous is False:
                if current_user.is_staff and current_user.is_active:
                    gogo = date.today() - self.get_last_timestamp(current_user)
                    if gogo > timedelta(days=PASS_EXPIRE_DAYS):
                        messages.warning(request, 'Your password expired '+str(gogo.days-PASS_EXPIRE_DAYS)+' days ago.')
                        return redirect('/admin/password_change/') # +str(gogo.days-settings.PASS_EXPIRE_DAYS)
        return response
    
    
    