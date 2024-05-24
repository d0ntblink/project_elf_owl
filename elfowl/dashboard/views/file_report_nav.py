from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repositories, repository_dependency_map, repository_info_map
from backend import main

class file_report_nav(TemplateView):
    report = 'file_report_nav.html'
    
    def get(self, request, magik_hash, file_name):
        template = loader.get_template(self.report)
        # Use regex to match the last part of the file_name
        file_information = repository_info_map.objects.filter(magik_hash=magik_hash, file_name__regex=r'.*{}$'.format(file_name))
        # Return the info to the template
        return HttpResponse(template.render({'file_information': file_information}, request=request))
