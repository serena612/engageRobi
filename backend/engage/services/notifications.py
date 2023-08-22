# coding: utf-8

from functools import wraps
from datetime import datetime
from django.db import transaction
from django.utils import timezone
from django.db.models import Q
from engage.account.constants import Transaction

from engage.account.constants import Transaction

# engage constants
from engage.core.constants import NotificationTemplate

# engage models
from engage.core.models import Notifications as NotificationsModel
from engage.account.models import UserNotification, User, UserTransactionHistory

# engage modules
from . import _with, FCM, cacheset, cached

# engage utils
from engage.utils import _safe_string_formatter

__all__ = (
    'Notifications',
    'notify_when',
)

cache_manager = cacheset["notifications"]


class Notifications(FCM):
    def __init__(self):
        super(FCM, self).__init__()

    @classmethod
    @_with(log=True, threading=False)
    def set(
            cls, event, user, notification, action, title, text, \
            url=None, image=None, template=None, notification_type='web', one_time=True
        ):
        # print("I SENDDDDDD")
        #@cached(manager=cache_manager)
        @transaction.atomic()
        def is_notification_created(user, action, notification, one_time):
            # save user notification data
           
            if one_time:
                package_ids = [x.id for x in notification.package.all()]
                if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                    
                    # obj, created = UserNotification.objects.get_or_create(
                    #     user=user,
                    #     notification=notification,
                    #     title=title,
                    #     text=text,
                    #     is_sent=True,
                    #     is_popup=notification.is_popup
                    # )
                    created = False
                    obj = UserNotification.objects.filter(
                        user=user,
                        notification=notification,
                        title=title,
                        text=text,
                        is_sent=True,
                        is_popup=notification.is_popup
                    ).order_by('-created').first()
                    
                    if not obj :
                        obj, created = UserNotification.objects.get_or_create(
                        user=user,
                        notification=notification,
                        title=title,
                        text=text,
                        is_sent=True,
                        is_popup=notification.is_popup
                    )

            else:
                now = datetime.now(tz=timezone.utc)

                if event == NotificationTemplate.DAILY:
                    package_ids = [x.id for x in notification.package.all()]
                    if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                    
                        UserNotification.objects.filter(
                            user=user,
                            is_claimed=True,
                            notification__template=NotificationTemplate.DAILY
                        ).delete()

                        #UserNotification.objects.filter(
                        #    user=user,
                        #    notification__template=NotificationTemplate.DAILY,
                        #    notification__action=NotificationAction.TEXT 
                    # ).delete()
                        
                        obj, created = UserNotification.objects.get_or_create(
                            user=user,
                            notification=notification,
                            title=title,
                            text=text,
                            is_sent=True,
                            is_claimed=notification.claim_instantly,
                            created__year=now.year,
                            created__month=now.month,
                            created__day=now.day,
                            is_popup=notification.is_popup
                        )

                    if created:
                        if notification.claim_instantly:
                            UserTransactionHistory.objects.create(
                                user=user,
                                amount=obj.notification.gifted_coins,
                                info = Transaction.NOTIFICATION_CLAIM+' '+notification.title
                            )
                       
                        cls.single(
                            user=user,
                            title=title,
                            message=text,
                            data={
                                'action': action,
                                'url': url,
                                'image': image,
                                'template': template,
                            },
                            type=notification_type
                        )

                    return obj, False

                elif event == NotificationTemplate.ONCE_A_MONTH:
                    package_ids = [x.id for x in notification.package.all()]
                    if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                        obj, created = UserNotification.objects.get_or_create(
                            user=user,
                            notification=notification,
                            title=title,
                            text=text,
                            is_sent=True,
                            created__year=now.year,
                            created__month=now.month,
                            is_popup=notification.is_popup
                        )
                elif event == NotificationTemplate.LOGIN:
                    package_ids = [x.id for x in notification.package.all()]
                    if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                        obj, created = UserNotification.objects.get_or_create(
                            user=user,
                            notification=notification,
                            title=title,
                            text=text,
                            is_sent=True,
                            created__day=now.day,
                            is_popup=notification.is_popup
                        )
                else:
                    package_ids = [x.id for x in notification.package.all()]
                    if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                        obj = UserNotification.objects.create(
                            user=user,
                            notification=notification,
                            title=title,
                            text=text,
                            is_sent=True,
                            is_popup=notification.is_popup
                        )
                    created = True if obj else False

            return obj, created

        obj, created = is_notification_created(user, action, notification, one_time)
        if created:
            if notification.claim_instantly:
                obj.is_claimed = True
                obj.save()

                UserTransactionHistory.objects.create(
                    user=user,
                    amount=obj.notification.gifted_coins,
                    info = Transaction.NOTIFICATION_CLAIM+' '+notification.title
                )

            cls.single(
                user=user,
                title=title,
                message=text,
                data={
                    'action': action,
                    'url': url,
                    'image': image,
                    'template': template,
                },
                type=notification_type
            )
        
        return obj

    @classmethod
    @_with(log=True, threading=True)
    def bulk(cls, notification):
        users = User.objects.all()
        package_ids = [x.id for x in notification.package.all()]
        for user in users:
            
            if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                    
                obj, created = UserNotification.objects.get_or_create(
                    user=user,
                    notification=notification,
                    title=notification.title,
                    text=notification.text,
                    is_sent=True,
                    is_claimed=notification.claim_instantly,
                    is_popup=notification.is_popup
                )

                if created:
                    if notification.claim_instantly:
                        UserTransactionHistory.objects.create(
                            user=user,
                            amount=obj.notification.gifted_coins,
                            info = Transaction.NOTIFICATION_CLAIM+' '+notification.title
                        )
                
                

        cls.multiple(
            users=users,
            title=notification.title,
            message=notification.text,
            data={
                'action': notification.action,
                'template': notification.template,
            },
            type="web"
        )
    
    @classmethod
    @_with(log=True, threading=True)
    def newbulk(cls, notification,users):
        for user in users:
               
                obj, created = UserNotification.objects.get_or_create(
                    user=user,
                    notification=notification,
                    title=notification.title,
                    text=notification.text,
                    is_sent=True,
                    is_claimed=notification.claim_instantly,
                    is_popup=notification.is_popup
                )

                if created:
                    if notification.claim_instantly:
                        UserTransactionHistory.objects.create(
                            user=user,
                            amount=obj.notification.gifted_coins,
                            info = Transaction.NOTIFICATION_CLAIM+' '+notification.title
                        )
                
                  

        cls.multiple(
            users=users,
            title=notification.title,
            message=notification.text,
            data={
                'action': notification.action,
                'template': notification.template,
            },
            type="web"
        )



    @classmethod
    @_with(log=True, threading=True)
    def send(cls, user, notification):
        package_ids = [x.id for x in notification.package.all()]
        if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids):
            obj, created = UserNotification.objects.get_or_create(
                user=user,
                notification=notification,
                title=notification.title,
                text=notification.text,
                is_sent=True,
                is_claimed=notification.claim_instantly,
                is_popup=notification.is_popup
            )

            if created:
                if notification.claim_instantly:
                    UserTransactionHistory.objects.create(
                        user=user,
                        amount=obj.notification.gifted_coins,
                        info=Transaction.NOTIFICATION_CLAIM+' '+notification.title,
                    )

            cls.multiple(
                users=[user],
                title=notification.title,
                message=notification.text,
                data={
                    'action': notification.action,
                    'template': notification.template,
                },
                type="web"
            )


def notify_when(events, is_route=True, is_one_time=True, extra={}, str_repl = {}, lnk_repl = ""):
    # TODO: requires a better solution
    if extra.get('event_date'):
        now = extra['event_date']
        extra_filter = {
            'event_date__month': now.month,
            'event_date__day': now.day,
        }
    else:
        extra_filter = {}

    if extra.get('created'):
        created = extra['created']
        extra_filter1 = {
            'created__month': created.month,
            'created__day': created.day,
        }
    else :
        extra_filter1 = {}
    

    def wrapper(fn):
        @wraps(fn)
        def decorated_route(request, *args, **kwargs):
            if any([True if event.value == 'login' else False for event in events]):
                fn(request, *args, **kwargs)

            if request.user.is_authenticated :
                for event in events:
                    notifications = NotificationsModel.objects.filter(
                        template=event,
                        is_active=True,
                        **extra_filter,
                        **extra_filter1
                    ).all()
                    
                    
                    for notification in notifications:
                        Notifications.set(**{
                                'event': event,
                                'user': request.user,
                                'notification': notification,
                                'action': notification.action,
                                'title': _safe_string_formatter(request.user, notification.title, extra=extra),
                                'text': _safe_string_formatter(request.user, notification.text, extra=extra),
                                'url': notification.url,
                                'image': notification.image.url if notification.image else None,
                                'template': notification.template,
                                'one_time': is_one_time,
                            })

            return fn(request, *args, **kwargs)

        @wraps(fn)
        def decorated_func(user, *args, **kwargs):
            # print("I REPLACEEEEE", args, kwargs)
            _user_notifications = []
            if user.is_authenticated:
                for event in events:
                    notifications = NotificationsModel.objects.filter(
                        template=event,
                        is_active=True,
                        **extra_filter,
                        **extra_filter1
                    ).all()
                    if str_repl != {}:
                        for i, notificationi in enumerate(notifications):
                            for key in str_repl:
                                notifications[i].text=notificationi.text.replace(key, str_repl[key])
                                # notifications[i].notification.text=notificationi.notification.text.replace(key, str_repl[key])
                            # notifications.save()

                    if lnk_repl != "":
                        for i, notificationi in enumerate(notifications):
                            notifications[i].link = lnk_repl
                            # notifications.save()

                    if extra_filter1 == {} :
                        for notification in notifications:
                            package_ids = [x.id for x in notification.package.all()]
                            if (user.subscription=='daily' and  1 in package_ids) or  (user.subscription=='weekly' and 2 in package_ids) or (user.subscription=='monthly' and 3 in package_ids) :
                                _user_notifications.append(Notifications.set(**{
                                    'event': event,
                                    'user': user,
                                    'notification': notification,
                                    'action': notification.action,
                                    'title': _safe_string_formatter(user, notification.title, extra=extra),
                                    'text': _safe_string_formatter(user, notification.text, extra=extra),
                                    'url': notification.url,
                                    'image': notification.image.url if notification.image else None,
                                    'template': notification.template,
                                    'one_time': is_one_time,
                                }))
                    else :
                        notification = notifications.order_by('-id').first()
                        get_notification = UserNotification.filter(
                            user=user,
                            notification=notification,
                            created__year=now.year,
                            created__month=now.month,
                            created__day=now.day
                        ).first()
                        if not get_notification :
                            _user_notifications.append(Notifications.set(**{
                                'event': event,
                                'user': user,
                                'notification': notification,
                                'action': notification.action,
                                'title': _safe_string_formatter(user, notification.title, extra=extra),
                                'text': _safe_string_formatter(user, notification.text, extra=extra),
                                'url': notification.url,
                                'image': notification.image.url if notification.image else None,
                                'template': notification.template,
                                'one_time': is_one_time,
                            }))
            # print("users nots: ", _user_notifications)
            return fn(user, _user_notifications, *args, **kwargs)

        return decorated_route if is_route else decorated_func
    return wrapper
