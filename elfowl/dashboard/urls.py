from django.urls import path
from dashboard.views.home import home
from dashboard.views.add_repo import add_repo
from dashboard.views.settings import settings
from dashboard.views.repo_report_nav import repo_report_nav
from dashboard.views.file_report_nav import file_report_nav
from dashboard.views.pr_monitor import pr_monitor

urlpatterns = [
    path('', home.as_view(), name='index'),
    path('add_repo', add_repo.as_view(), name='add_repo'),
    path('settings', settings.as_view(), name='settings'),
    path('report/<str:magik_hash>', repo_report_nav.as_view(), name='repo_report_nav'),
    path('report/<str:magik_hash>/<str:file_name>', file_report_nav.as_view(), name='file_report_nav'),
    path('pr_monitor/<int:repo_id>', pr_monitor.as_view(), name='pr_monitor_repo')
]
