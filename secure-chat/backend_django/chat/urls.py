from django.urls import path
from .views import RotateGroupKeyView, SendMessageView, ReceiveMessagesView
from .views import CreateGroupView, ListGroupsView

urlpatterns = [
    path('send/', SendMessageView.as_view(), name='send-message'),
    path('inbox/', ReceiveMessagesView.as_view(), name='receive-messages'),
    path('groups/create/', CreateGroupView.as_view(), name='create-group'),
    path('groups/', ListGroupsView.as_view(), name='list-groups'),
        path('groups/<int:group_id>/rotatekey/', RotateGroupKeyView.as_view(), name='rotate-group-key'),
]
