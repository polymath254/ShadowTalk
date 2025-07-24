from django.urls import include, path
from .views import RegisterView, LoginView
from .views import UserListView, UserDetailView
from .views import DeleteAccountView
from .views import StorePairTokenView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('lookup/', UserListView.as_view(), name='user-list'),
    path('lookup/<str:username>/', UserDetailView.as_view(), name='user-detail'),
    path('delete/', DeleteAccountView.as_view(), name='delete-account'),
    path('pairtoken/', StorePairTokenView.as_view(), name='store-pair-token'),
]
