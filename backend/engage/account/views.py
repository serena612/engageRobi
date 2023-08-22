from datetime import timedelta
from django.db.models import Count
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.db.models import Q, Sum, Func, F, Value, CharField, OuterRef, \
    Subquery, Case, When
from django.db.models.expressions import Exists
from django.db.models.functions import Coalesce
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from engage.settings.base import AXES_COOLOFF_TIME

from .models import UserGameLinkedAccount, User, FriendList, \
    UserBattlePassMission
from engage.core.constants import WinAction
from engage.core.models import BattlePass, Mission, BattlePassLevel,BattlePassMission
from engage.operator.models import PurchaseCoin, RedeemPackage
from django.contrib import messages
from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe
from engage.settings.base import SHOWADS
from datetime import datetime
from engage.core.models import Game, FeaturedGame, Event
from engage.tournament.models import Tournament, TournamentPrize
from django.db.models import F, Q,Prefetch
from engage.operator.models import OperatorAd
from engage.account.models import UserTransactionHistory

def public_profile_view(request, uid):
    try:
        user = User.objects.get(uid=uid)

    except User.DoesNotExist:
        return redirect('/')

    if request.user.is_authenticated and request.user == user:
        return redirect(reverse('profile'))

    friend_status = None
    if request.user.is_authenticated:
        friend = FriendList.objects.filter(
            Q(user=request.user) & Q(friend__uid=uid) |
            Q(friend=request.user) & Q(user__uid=uid)
        ).first()

        if friend:
            friend_status = friend.status

    return render(request, 'public-profile.html', { 'user': request.user,
                                                   'selected_user':user,
                                                   'friend_status': friend_status})


# TODO: Refactor
@login_required(login_url='/')
def profile_view(request):
    if request.user.is_staff or  request.user.is_superuser:
        return redirect('/auth/logout/')
    now = timezone.now()
    user = request.user

    battle_pass = BattlePass.objects.get_active().prefetch_related(
        'battlepasslevel_set'
    ).first()

    user_bp_mission = UserBattlePassMission.objects.filter(
        user=user,
        bp_mission__mission=OuterRef('id'),
        bp_mission__battle_pass__created=now
    ).distinct()
    
    mission_count= Mission.objects.count()
   
    date = now.date()
    missions = Mission.objects.filter(
        battlepassmission__date__range=[now.date(), now.date() +
                                        timedelta(days=len(WinAction.choices)-1)]
    ).distinct('id').annotate(
        active_till=Func(
            F('battlepassmission__date'), Value('MON DD, YYYY 23:59:59'),
            function='to_char',
            output_field=CharField()
        ),
        is_completed=Subquery(user_bp_mission.values('is_completed')[:1])
    ).all()


   
        
    battle_pass_levels = BattlePassLevel.objects.filter(
        battle_pass=battle_pass
    ).distinct('level').in_bulk(field_name='level')
    activity_points = user.userbattlepassmission_set.filter(
        bp_mission__battle_pass=battle_pass,
    ).aggregate(
        activity_points=Coalesce(Sum('points'), 0)
    )
    activity_points = activity_points.get('activity_points', 0)
    max_battlepass_level = range(1, battle_pass.max_level + 1) if battle_pass else None
    is_battlepass_vip = battle_pass and battle_pass.is_user_vip(request.user)

    purchase_coins = PurchaseCoin.objects.all()
    redeem_packages = RedeemPackage.objects.all()
    if request.user and request.user.is_authenticated:
        user_uid = request.user.uid
    else:
        user_uid = ""
    return render(request, 'profile.html', {'battle_pass': battle_pass,
                                            'missions': missions,
                                            'max_battlepass_level': max_battlepass_level,
                                            'battle_pass_levels': battle_pass_levels,
                                            'activity_points': activity_points,
                                            'purchase_coins': purchase_coins,
                                            'redeem_packages': redeem_packages,
                                            'is_battlepass_vip': is_battlepass_vip,
                                            'show_ads': SHOWADS,
                                            'user_uid': user_uid}) # TODO: fix


@require_http_methods(['POST'])
def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')

    #TODO: temporary for demo
    try:
        user = User.objects.get(
            username__iexact=username,
            region=request.region,
            is_staff=True
        )
    except User.DoesNotExist:
        return redirect('/')

    login(request, user)
    
    user.last_login = timezone.now()
    user.save()

    # user = authenticate(username=username, password=password)
    # if user is not None:
    #     login(request, user)

    return redirect('/')


@login_required
def logout_view(request):
    request.user.app_fcm_token = None
    request.user.web_fcm_token = None
    request.user.save()
    request.session.flush()
    logout(request)
    response = redirect('/')  # django.http.HttpResponse
    response.set_cookie(key='logged_out', value=datetime.now().isoformat())
    return response

    #request.COOKIES['logged_out'] = datetime.now().isoformat()

    #return redirect('/')


def logout2_view(request):
    request.session.flush()
    logout(request)
    response = redirect('/')  # django.http.HttpResponse
    response.set_cookie(key='logged_out', value=datetime.now().isoformat())
    return response
    #request.COOKIES['logged_out'] = datetime.now().isoformat()
    #return redirect('/register')

@login_required
def set_game_linked_account(request):
    account = request.POST.get('account')
    game = request.POST.get('game')
    tournament = request.POST.get('tournament')


    try:
        user_game_account = UserGameLinkedAccount.objects.update_or_create(
            user=request.user,
            game_id=game,
            tournament_id=tournament,
            defaults={'account': account}
        )
    # except IntegrityError:
    except Exception as e:
        print(e)
        return JsonResponse({'error': 'Something went wrong'}, status=400)

    return JsonResponse({}, status=200)


def prizes_view(request):
    if request.user.is_staff or request.user.is_superuser :
        return redirect('/auth/logout/')  

    purchase_coins = PurchaseCoin.objects.filter(
        operator__region=request.region
    ).all()
    
    redeem_packages = RedeemPackage.objects.filter(
        operator__region=request.region
    ).all()
    return render(request, 'prizes.html', {
        'purchase_coins': purchase_coins,
        'redeem_packages': redeem_packages
    })

def winners_view(request):
    if request.user.is_staff or request.user.is_superuser :
        return redirect('/auth/logout/')  
    # now = timezone.now()
    # games = Game.objects.all()
    # previous_tournaments = Tournament.objects.select_related('game').prefetch_related(
    #     'tournamentparticipant_set',
    #     Prefetch(
    #         'tournamentprize_set',
    #         queryset=TournamentPrize.objects.order_by('position')
    #     )
    # ).filter(regions__in=[request.region],end_date__lt=now).order_by('name')

    # return render(request, 'winners.html', {'games': games,
    #                                       'previous_tournaments':previous_tournaments })
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


    return render(request, 'winners.html', {'featured_games': featured_games,
                                          'games': games,
                                          'ad': ad,
                                          'events': events,
                                          'previous_tournaments':previous_tournaments,
                                          'user_id': user_id,
                                          'show_ads': SHOWADS,
                                          'user_uid': user_uid,
                                          'is_ad_google': is_ad_google,
                                          'is_ad_engage':is_ad_engage})


def view_404(request, exception=None):
    return redirect('/')

def lockout(request, credentials, *args, **kwargs):
    messages.error(request, mark_safe(_('You have been locked out for '+str(int(AXES_COOLOFF_TIME*60))+' minute(s)!<br>Please try again later.')))
    return redirect('/admin')
