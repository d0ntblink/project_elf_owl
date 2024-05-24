from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repositories, repository_dependency_map, repository_info_map
from backend import main

class repo_report_nav(TemplateView):
    report = 'repo_report_nav.html'
    
    
    def get(self, request, magik_hash):
        template = loader.get_template(self.report)
        #  get all the rows in repository_info_map where magik_hash is equal to the magik_hash
        repo_dependencies = repository_dependency_map.objects.filter(magik_hash=magik_hash)
        repo_file_names = [i.file_name.split("/")[-1] for i in\
            repository_info_map.objects.filter(magik_hash=magik_hash)]
        # return the info to the template
        return HttpResponse(template.render({'file_names': repo_file_names,
                                             'magik_hash': magik_hash,
                                             'repo_dependencies' : repo_dependencies}, request=request))
