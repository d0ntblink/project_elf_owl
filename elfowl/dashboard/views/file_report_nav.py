from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repository_info_map, repositories
import json

class file_report_nav(TemplateView):
    report = 'file_report_nav.html'
    
    def get(self, request, magik_hash, file_name):
        template = loader.get_template(self.report)
        file_information = repository_info_map.objects.filter(
            magik_hash=magik_hash,
            file_name__regex=r'.*{}$'.format(file_name)
        )
        repo_name = repositories.objects.get(magik_hash=magik_hash).repo_name
        return HttpResponse(template.render({
            'file_information': file_information,
            'file_name': file_name,
            'repo_name': repo_name,
            'magik_hash': magik_hash
        }, request=request))
