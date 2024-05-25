from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repositories, repository_dependency_map, repository_info_map
from backend import main

class repo_report_nav(TemplateView):
    report = 'repo_report_nav.html'
    
    def get(self, request, magik_hash):
        template = loader.get_template(self.report)
        # Get all the rows in repository_info_map where magik_hash is equal to the magik_hash
        repo_name = repositories.objects.get(magik_hash=magik_hash).repo_name
        file_dict = {
            item.file_name.split("/")[-1]: ["/".join(item.file_name.split("/")[5:])\
                ,item.file_name.split(".")[-1]]
            for item in repository_info_map.objects.filter(magik_hash=magik_hash)
        }
        print(file_dict)
        # Return the info to the template
        return HttpResponse(template.render({
            'repo_name': repo_name,
            'file_dict': file_dict,
            'magik_hash': magik_hash,
        }, request=request))
