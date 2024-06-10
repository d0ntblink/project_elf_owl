from django.urls import path, re_path
from dashboard.views.home import home, about, contact, documentation
from dashboard.views.add_repo import add_repo
from dashboard.views.settings import SettingsView, GetSessionValueView, DeleteSessionValueView
from dashboard.views.repo_report_nav import repo_report_nav
from dashboard.views.file_report_nav import file_report_nav
from dashboard.views.pr_monitor import pr_monitor
from dashboard.views.dependencies_report import dependencies_report

urlpatterns = [
    path('', home.as_view(), name='index'),
    path('add_repo', add_repo.as_view(), name='add_repo'),
    path('about', about.as_view(), name='about'),
    path('settings', SettingsView.as_view(), name='settings'),
    path('settings/get/<str:key>/', GetSessionValueView.as_view(), name='get_session_value'),
    path('settings/delete/<str:key>/', DeleteSessionValueView.as_view(), name='delete_session_value'),
    path('documentation', documentation.as_view(), name='documentation'),
    path('contact', contact.as_view(), name='contact'),
    path('report/<str:magik_hash>', repo_report_nav.as_view(), name='repo_report_nav'),
    path('dependencies/<str:magik_hash>', dependencies_report.as_view(), name='dependencies_report'),
    re_path(r'^report/(?P<magik_hash>[a-zA-Z0-9]+)/(?P<file_name>.+)$', file_report_nav.as_view(), name='file_report_nav'),
    path('pr_monitor/<int:repo_id>', pr_monitor.as_view(), name='pr_monitor_repo')
]
