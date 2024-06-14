from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repositories, repository_dependency_map, repository_info_map

class repo_report_nav(TemplateView):
    template_name = 'repo_report_nav.html'
    
    def get(self, request, magik_hash):
        template = loader.get_template(self.template_name)
        try:
            repo = repositories.objects.get(magik_hash=magik_hash)
            repo_name = repo.repo_name
            file_dict = {
                item.file_name.split("/")[-1]: ["/".join(item.file_name.split("/")[4:]), item.file_name.split(".")[-1]]
                for item in repository_info_map.objects.filter(magik_hash=magik_hash)
            }
            context = {
                'repo_name': repo_name,
                'file_dict': file_dict,
                'magik_hash': magik_hash,
            }
            return HttpResponse(template.render(context, request=request))
        except repositories.DoesNotExist:
            return HttpResponse('Repository not found', status=404)
