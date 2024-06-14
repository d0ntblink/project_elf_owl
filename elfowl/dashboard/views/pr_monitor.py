from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from backend import main
from dashboard.models import repositories, repository_dependency_map, repository_info_map
import logging

class pr_monitor(TemplateView):
    home = 'index.html'
    
    
    def get(self, request):
        template = loader.get_template(self.home)
        return HttpResponse(template.render(request=request))