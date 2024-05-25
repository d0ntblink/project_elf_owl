from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repositories, repository_dependency_map
from backend import main
import json

class dependencies_report(TemplateView):
    report = 'dependencies_report.html'
    
    def get(self, request, magik_hash):
        template = loader.get_template(self.report)
        # Get all the rows in repository_info_map where magik_hash is equal to the magik_hash
        repo_name = repositories.objects.get(magik_hash=magik_hash).repo_name
        dependencies_information = repository_dependency_map.objects.filter(magik_hash=magik_hash)[0]
        dependencies_list_ver = json.loads(dependencies_information.dependencies_json)
        dependencies_vuln_report = json.loads(dependencies_information.dependencies_cve_vuln_found_json)
        # Return the info to the template
        return HttpResponse(template.render({
            'repo_name': repo_name,
            'magik_hash': magik_hash,
            'dependencies_list_ver': dependencies_list_ver,
            'dependencies_vuln_report': dependencies_vuln_report,
        }, request=request))
