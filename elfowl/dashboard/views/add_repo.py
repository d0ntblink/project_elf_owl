from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from backend import main
from dashboard.models import repositories, repository_dependency_map, repository_info_map
import logging
from backend import test_secrets as secrets


class add_repo(TemplateView):
    logger = logging.getLogger("addRepoView")
    logger.setLevel(logging.DEBUG)
    add_repo = 'add_repo.html'
    db_location = "/elfowl/db.sqlite3"
    repo_locations = "/elfowl/data/downloads"
    image_store_location = "/elfowl/data/images"
    openai_model = "gpt-3.5-turbo-1106"
    run_backend = main.runBackend(db_location,
                                repository_table_name=f"dashboard_{repositories.__name__}",
                                repository_info_table_name=f"dashboard_{repository_info_map.__name__}",
                                repository_dependency_table_name=f"dashboard_{repository_dependency_map.__name__}",
                                repo_locations=repo_locations,
                                image_store_location=image_store_location,
                                openai_model=openai_model,
                                api_key=secrets.apikey,
                                org_id=secrets.orgid,
                                vuln_code_host="nginx",
                                truffles_config_file="/elfowl/truffles_config.yml",
                                max_threads=10)
    run_backend.threadManager.create_a_pool("add_repo")
        
    
    def get(self, request):
        template = loader.get_template(self.add_repo)
        return HttpResponse(template.render(request=request))
    
    def post(self, request):
        template = loader.get_template(self.add_repo)
        input_repo_remote = request.POST.get('input_repo_remote')
        input_repo_branch = request.POST.get('input_repo_branch')
        self.run_backend.new_repo_sequence(input_repo_remote, input_repo_branch)
        return HttpResponse(template.render(request=request))