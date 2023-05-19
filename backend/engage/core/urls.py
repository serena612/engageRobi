from django.urls import path, include
from rest_framework.routers import SimpleRouter

from . import api, views


router = SimpleRouter()
router.register('avatars', api.AvatarViewSet)
router.register('html5_games', api.HTML5GameViewSet)
router.register('contact', api.ContactViewSet, basename='contact')
router.register('featured_games', api.FeaturedGameViewSet)


urlpatterns = [
    path('', views.home_view, name='home'),
    path('secured', views.secured_view, name='secured'),
    path('about', views.about_view, name='about'),
    path('faq', views.faq_view, name='faq'),
    path('headers', views.header_view, name='headers'),
    path('terms', views.terms_view, name='terms'),
    path('privacy', views.privacy_view, name='privacy'),
    path('disclaimer', views.disclaimer_view, name='disclaimer'),
    path('html5/<str:game>', views.html5_game_view, name='html5game'),
    path('register', views.register_view, name='register'),
    path('wait', views.waiting_view, name='wait'),
    path('clear', views.clear_session_view, name='clear'),
    path('newregister', views.new_register_view, name='new_register'),
    path('testregister', views.test_register_view, name='test_register'),
    # firebase
    path('firebase-messaging-sw.js', views.firebase_sw_view),
    path('api/', include(router.urls)),
]