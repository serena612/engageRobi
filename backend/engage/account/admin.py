from django.contrib import admin
from django.db.models import Sum
from django.contrib.auth.admin import UserAdmin
from axes.models import AccessAttempt, AccessLog, AccessFailureLog
from axes.admin import AccessAttemptAdmin, AccessLogAdmin, AccessFailureLogAdmin
from django.utils.translation import ugettext_lazy as _
from . import models
from engage.core.models import  Mission
from .constants import (
    CoinTransaction
)
from django.db.models.functions import Coalesce
class UserFriendInline(admin.TabularInline):
    model = models.FriendList
    min_num = 0
    fk_name = 'user'


class UserTransactionInline(admin.TabularInline):
    model = models.UserTransactionHistory
    fields = ('created','amount','coins', 'action','details')
    readonly_fields = ('action', 'amount', 'coins','created','details')

    def has_add_permission(self, request, obj):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def coins(self, obj):
        now = obj.created
        coins_history = models.UserTransactionHistory.objects.filter(
            user=obj.user,
            created__date = now.date()
        ).aggregate(total_amount=Coalesce(Sum('amount'), 0))
        return coins_history.get('total_amount', 0)
       

    def details(self, obj):
        now = obj.created
        notifications = models.UserBattlePassMission.objects.filter(user=obj.user,
                                                                    created__year=obj.created.year,
                                                                    created__month=obj.created.month,
                                                                    created__day=obj.created.day
                                                                    ).values_list('bp_mission__mission__id').distinct()
        missions = Mission.objects.filter(id__in=notifications)
        str_details=""
        for note in missions :
            if(str_details !="") : 
                str_details = str_details +","+ note.name
            else :
                str_details = note.name   
         
        coins_history = models.UserTransactionHistory.objects.filter(
            user=obj.user,
            created__date=now,
            id=obj.id
        ).first()
        if coins_history :
            if str_details !="" and coins_history.info and coins_history.info not in str_details: 
                str_details = str_details +","+ coins_history.info
            elif coins_history.info and coins_history.info not in str_details:
                str_details = coins_history.info   
         
        return str_details    

@admin.register(models.User)
class UserAdmin(UserAdmin):
    list_display = ('username', 'nickname', 'subscription','coins', 'mobile','date_joined', 'last_login', 'last_updated')
    readonly_fields = ('last_login', 'date_joined', 'coins','game_nicknames', 'subscription')
    fieldsets = (
        (None, {'fields': ('avatar', 'nickname', 'username', 'password', 'coins', 'subscription', 'last_login', 'date_joined','game_nicknames')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'mobile', 'country')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        })
    )
    search_fields = ['nickname','mobile']
    inlines = [UserTransactionInline, UserFriendInline]

    def date_joined(self, obj):
        return obj.created
    date_joined.short_description = 'Date Joined'

    def last_updated(self, obj):
        return obj.modified
    last_updated.short_description = 'Last Updated'



class MiniUserAdmin(UserAdmin):
    list_display = ('username', 'date_joined', 'last_login', 'last_updated')
    list_filter = ['is_active', 'is_superuser', ]
    readonly_fields = ('last_login', 'date_joined')
    fieldsets = (
        (None, {'fields': ('username', 'password', 'last_login', 'date_joined')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'mobile', 'country')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_superuser', 'groups', 'user_permissions'),
        })
    )
    inlines = []

    def date_joined(self, obj):
        return obj.created
    date_joined.short_description = 'Date Joined'

    def last_updated(self, obj):
        return obj.modified
    last_updated.short_description = 'Last Updated'

    def get_queryset(self, request):
        return self.model.objects.filter(is_staff=True)
    
    
    def save_model(self, request, obj, form, change):
        if request.user.is_superuser:
            obj.is_staff = True
            obj.save()

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            if obj is not None and obj == request.user:
                return False
            else:
                return True
        else:
            return False
    # def has_change_permission(self, request, user=None):
    #     if request.user.is_staff and '/admin/account/staffuser/'+str(request.user.id)+'/password/' in request.path:
    #         return True
    #     return super(UserAdmin, self).has_change_permission(request, user)
    # def has_view_permission(self, request, user=None):
    #     if request.user.is_staff and '/admin/account/staffuser/'+str(request.user.id)+'/change/' in request.path:
    #         return True
    #     return super(UserAdmin, self).has_view_permission(request, user)
    
    
   

class StaffUser(models.User):
    class Meta:
        proxy = True
        verbose_name = 'CMS User'

admin.site.register(StaffUser, MiniUserAdmin)

class EndUserAdmin(UserAdmin):
    list_display = ('username', 'nickname','coins', 'mobile', 'subscription', 'date_joined', 'last_login', 'last_updated')
    list_filter = ['is_active', 'is_superuser', ]
    readonly_fields = ('last_login', 'date_joined', 'coins','game_nicknames', 'subscription')
    fieldsets = (
        (None, {'fields': ('avatar', 'nickname', 'username', 'password', 'coins', 'subscription', 'last_login', 'date_joined','game_nicknames')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'mobile', 'country')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_superuser', 'groups', 'user_permissions'),
        })
    )
    inlines = [UserTransactionInline, UserFriendInline]

    def date_joined(self, obj):
        return obj.created
    date_joined.short_description = 'Date Joined'

    def last_updated(self, obj):
        return obj.modified
    last_updated.short_description = 'Last Updated'

    def get_queryset(self, request):
        return self.model.objects.filter(is_staff=False)
    
    def has_add_permission(self, request, obj=None):
        return False

class EndUser(models.User):
    class Meta:
        proxy = True
        verbose_name = 'Engage Subscriber'

admin.site.register(EndUser, EndUserAdmin)    


class superAccessAttemptAdmin(AccessAttemptAdmin):
    def get_queryset(self, request):
        return self.model.objects.filter(path_info="/admin/login/")
    def get_model_perms(self, request):
        """
        Return empty perms dict thus hiding the model from admin index.
        """
        return {}

admin.site.register(AccessAttempt, superAccessAttemptAdmin)


class superAccessLogAdmin(AccessLogAdmin):
    def get_queryset(self, request):
        return self.model.objects.filter(path_info="/admin/login/")

admin.site.register(AccessLog, superAccessLogAdmin)

class superAccessFailureLogAdmin(AccessFailureLogAdmin):
    def get_queryset(self, request):
        return self.model.objects.filter(path_info="/admin/login/")

admin.site.register(AccessFailureLog, superAccessFailureLogAdmin)

