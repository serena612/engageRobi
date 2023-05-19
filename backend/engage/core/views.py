from django.db.models import F, Q,Prefetch
from django.http import HttpResponse, Http404,HttpResponseForbidden
from django.shortcuts import render, redirect
from django.utils import timezone
from engage.account.models import User
from engage.tournament.models import Tournament,TournamentPrize
from django.contrib.auth import login
from engage.account.api import grant_referral_gift
from engage.core.models import HTML5Game, Event, FeaturedGame, Game
from engage.core.constants import NotificationTemplate
from engage.operator.models import OperatorAd
from engage.services import notify_when
from engage.settings.base import SHOWADS
from engage.account.constants import SubscriptionPlan

from engage.account.models import UserTransactionHistory
from datetime import datetime
from datetime import timedelta
from django.contrib.auth import get_user_model, login
from engage.settings.base import LANGUAGE_CODE
from django.utils.translation import get_language
import uuid

from engage.account.api import do_register


UserModel = get_user_model()

@notify_when(events=[
    NotificationTemplate.HOME,
    NotificationTemplate.HOW_TO_USE
])

def attempt_login_register(request):
    if 'msisdn' not in request.session or request.user.is_authenticated:
      print("inside first if")
      return
    try:
        mobilen = request.session['msisdn']
        request.user = mobilen
        user = UserModel.objects.filter(
            mobile__iexact=mobilen,
            region=request.region
        ).first()
        if user:
            # user found attempt direct login
            usermob = str(user.mobile)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        else:
            # user not found attempt registration
            usermob = mobilen
            do_register(None, request, usermob, SubscriptionPlan.FREE)
    
    except UserModel.DoesNotExist:
        usermob = mobilen
        do_register(None, request, usermob, SubscriptionPlan.FREE)

def home_view(request):
    print("msisdn", request.user)
    #request.COOKIES['logged_out'] = datetime.now().isoformat()
    #print("COOKIE",request.COOKIES['logged_out'])


    if request.user: #or request.user.is_authenticated:  #request.user
        print("inside first if")
        #print(logged_out)
        print('logged_out' in request.COOKIES)
        if 'logged_out' in request.COOKIES:  # check if log out date is present
          print("inside second if")
          if datetime.now() - datetime.fromisoformat(request.COOKIES['logged_out']) < timedelta(minutes=3): # check if expired
              # show logged out page
              print("pass")
              pass
          else:
              # attempt login/register
              print("attempt login")
              attempt_login_register(request)
        else:
            # attempt login/register
            print("else")
            attempt_login_register(request)
            
    now = timezone.now()

    featured_games = FeaturedGame.objects.all()
    games = Game.objects.all()
    ad = OperatorAd.objects.filter(
        (Q(start_date__gte=now) & Q(end_date__lte=now)) |
        (Q(start_date__isnull=True) & Q(end_date__isnull=True)),
        regions__in=[request.region]
    ).order_by('?').first()
    events = Event.objects.filter(
        regions__in=[request.region]
    ).all().order_by('?')[:20]

    previous_tournaments = Tournament.objects.select_related('game').prefetch_related(
        'tournamentparticipant_set',
        Prefetch(
            'tournamentprize_set',
            queryset=TournamentPrize.objects.order_by('position')
        )
    ).filter(regions__in=[request.region],end_date__lt=now).order_by('name')
    if 'user_id' in request.session:
        user_id = True
    else:
        user_id = False
    if request.user and request.user.is_authenticated :
        user_uid = request.user.uid
    else:
        user_uid = ""

    if request.user.is_authenticated :
        transaction = UserTransactionHistory.objects.filter(user=request.user).first()
        print("transaction", transaction, "viewed", transaction.engage_viewed())
        
        if transaction.engage_viewed() < 3:
            is_ad_engage = 0
        else:
            is_ad_engage = 1
        if transaction.ads_clicked()+transaction.ads_viewed() < 3:
            is_ad_google = 0
        else:
            is_ad_google = 1
    
    else:
        is_ad_engage = 1
        is_ad_google = 1

    lang_code = get_language()
    print("lang_code", lang_code)

    return render(request, 'index.html', {'featured_games': featured_games,
                                          'games': games,
                                          'ad': ad,
                                          'events': events,
                                          'previous_tournaments':previous_tournaments,
                                          'user_id': user_id,
                                          'show_ads': SHOWADS,
                                          'user_uid': user_uid,
                                          'is_ad_google': is_ad_google,
                                          'is_ad_engage':is_ad_engage,
                                          'lang_code': lang_code})


def secured_view(request):
   return render(request, 'secured.html', {})

    
def about_view(request):
    if  request.user.is_staff or request.user.is_superuser :
        return redirect('/auth/logout/')  
    return render(request, 'about.html', {})


def register_view(request):
    if request.user and request.user.is_authenticated or ('user_id' in request.session and 'renewing' not in request.session):
       return redirect('/')
    elif 'headeren' not in request.session and request.is_secure() and 'msisdn' not in request.session:
        print("uri",request.build_absolute_uri())
        gaga = request.build_absolute_uri().replace('https', 'http')
        print("gaga", gaga)
        # return redirect(gaga)
        return redirect(gaga)
    else :
        # print(request.headers)
        refid = request.GET.get('referrer')
        if refid != "":
            print("uid", User.uid.id)
            ref1 = User.objects.filter(uid=refid).query
            print("ref1",ref1)
            ref = User.objects.filter(uid=refid).first()
        else:
            ref = None
        if ref:
            request.session['refid'] = ref.id
        if 'msisdn' in request.session:
            print(request.session['msisdn'])
            usermob = request.session['msisdn']
            do_register(None, request, usermob, SubscriptionPlan.FREE)
            #return render(request, 'register2.html', {'wifi':False, 'refid':refid, 'msisdn':request.session['msisdn']})
        return render(request, 'register.html', {'wifi':True, 'refid':refid})

def test_register_view(request):
    if request.user and request.user.is_authenticated or ('user_id' in request.session and 'renewing' not in request.session):
       return redirect('/')
    else :
        refid = request.GET.get('referrer')
        ref = User.objects.filter(uid=refid).first()
        if ref:
            request.session['refid'] = ref.id
    if 'msisdn' in request.session:  
        print(request.session['msisdn'])
        return render(request, 'register2.html', {'wifi':False, 'refid':refid, 'msisdn':request.session['msisdn']})
    else:
        return render(request, 'register2.html', {'wifi':False, 'refid':refid, 'msisdn':'DummyNumberHere'})
    
    
def waiting_view(request):
    # print('user_id' in request.session)
    if not 'user_id' in request.session:
        return redirect('/')
    elif (request.user and request.user.is_active):
        userid = request.session.pop('user_id', None)
        return redirect('/')
    else :
        # print(request.headers)
        # print("user", request.user)
        user = User.objects.get(pk=request.session['user_id'])
        return render(request, 'wait.html', {'wifi':True, 'user':user})

def clear_session_view(request):
    if 'user_id' in request.session:
        userid = request.session.pop('user_id', None)
        
        if 'subscribed' in request.session:
            subscribed = request.session.pop('subscribed', None)
            print("subscribed =", subscribed)
            if subscribed==1:
                subscription = SubscriptionPlan.FREE
            elif subscribed==2:
                subscription = SubscriptionPlan.PAID1
            elif subscribed==3:
                subscription = SubscriptionPlan.PAID2
            print('successfully subscribed!')
            user = User.objects.get(pk=userid)
            user.is_active=True
            user.subscription=subscription
            user.save()
            if 'refid' in request.session:
                grant_referral_gift(user, request.session['refid'])
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('/')
        else:
            request.session.flush()
            request.COOKIES['logged_out'] = datetime.datetime.now().isoformat()
    return redirect('/register')

def new_register_view(request):
    
    if request.user and request.user.is_authenticated or ('user_id' in request.session and 'renewing' not in request.session):
        return redirect('/')
    elif 'headeren' not in request.session and request.is_secure() and 'msisdn' not in request.session:
        gaga = request.build_absolute_uri().replace('https', 'http')
        # return redirect(gaga)
    else :
        refid = request.GET.get('referrer')
        ref = User.objects.filter(uid=refid).first()
        if ref:
            request.session['refid'] = ref.id
        if 'msisdn' in request.session:
            print(request.session['msisdn'])
            return render(request, 'register3.html', {'wifi':False, 'refid':refid, 'msisdn':request.session['msisdn']})
        return render(request, 'register1.html', {'refid':refid})


def header_view(request):
    strr = "<html>"
    for k in request.headers:
        strr += str(k) + ': '+ str(request.headers[k])
        strr += "<br>"
    strr += "</html>"
    return HttpResponse(strr)

def faq_view(request):
    return render(request, 'FAQ.html', {})


def terms_view(request):
    return render(request, 'terms.html', {})


def privacy_view(request):
    return render(request, 'privacy.html', {})


def disclaimer_view(request):
    return render(request, 'disclaimer.html', {})


def html5_game_view(request, game):
    try:
        html5_game = HTML5Game.objects.filter(
            regions__in=[request.region]
        ).get(slug__iexact=game)
    except HTML5Game.DoesNotExist:
        raise Http404

    return redirect(f'/html5_game/{html5_game.slug}/')


def firebase_sw_view(request):
    return HttpResponse("""
        importScripts('https://www.gstatic.com/firebasejs/9.17.1/firebase-app-compat.js');
        importScripts('https://www.gstatic.com/firebasejs/9.17.1/firebase-messaging-compat.js');
        importScripts('https://www.gstatic.com/firebasejs/9.17.1/firebase-analytics-compat.js');

        firebase.initializeApp({
            apiKey: "AIzaSyClFi6oYdwKrbbTYBSNRdbYmLXJ4uR-vHI",
            authDomain: "engageplaywin-4b74b.firebaseapp.com",
            projectId: "engageplaywin-4b74b",
            storageBucket: "engageplaywin-4b74b.appspot.com",
            messagingSenderId: "729860295401",
            appId: "1:729860295401:web:b732dc0c7618190cf53e78",
            measurementId: "G-C0XVDBF16H"
        });

        const messaging = firebase.messaging();
       
    """, status=200, content_type='application/javascript')


def view_404(request, exception=None): 
    return redirect('/')

def view_403(request, exception=None): 
    return redirect('/admin')

# def error_403(request, exception):
#         return render(request,'403.html') 
