from django.urls import path
from dashboard.views.indexview import IndexView

urlpatterns = [
    path('', IndexView.as_view(), name='index'),
]
