from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from backend import main
from dashboard.models import repositories, repository_dependency_map, repository_info_map
import logging

class add_repo(TemplateView):
    logger = logging.getLogger("addRepoView")
    logger.setLevel(logging.DEBUG)
    add_repo = 'add_repo.html'
    db_location = "/elfowl/db.sqlite3"
    repo_locations = "/elfowl/data/downloads"
    image_store_location = "/elfowl/data/images"

    def get(self, request):
        template = loader.get_template(self.add_repo)
        session_values = {
            'apikey': request.session.get('apikey'),
            'orgid': request.session.get('orgid'),
            'model': request.session.get('model')
        }
        all_values_present = all(session_values.values())

        context = {
            'session_values': session_values,
            'all_values_present': all_values_present
        }
        return HttpResponse(template.render(context, request))

    def post(self, request):
        template = loader.get_template(self.add_repo)
        input_repo_remote = request.POST.get('input_repo_remote')
        input_repo_branch = request.POST.get('input_repo_branch')
        
        # Retrieve values from the session
        api_value = request.session.get('apikey')
        org_value = request.session.get('orgid')
        model_value = request.session.get('model')
        
        # Log the retrieved session values (for debugging purposes)
        self.logger.debug(f"API Key: {api_value}")
        self.logger.debug(f"Org ID: {org_value}")
        self.logger.debug(f"Model: {model_value}")

        # Run backend initialization with session values
        run_backend = main.runBackend(
            db_location=self.db_location,
            repository_table_name=f"dashboard_{repositories.__name__}",
            repository_info_table_name=f"dashboard_{repository_info_map.__name__}",
            repository_dependency_table_name=f"dashboard_{repository_dependency_map.__name__}",
            repo_locations=self.repo_locations,
            image_store_location=self.image_store_location,
            openai_model=model_value, #from session
            api_key=api_value, #from session
            org_id=org_value, #from session
            vuln_code_host="nginx",
            truffles_config_file="/elfowl/truffles_config.yml",
            max_threads=10
        )
        run_backend.threadManager.create_a_pool("add_repo")

        run_backend.new_repo_sequence(input_repo_remote, input_repo_branch)
        
        session_values = {
            'apikey': api_value,
            'orgid': org_value,
            'model': model_value
        }
        all_values_present = all(session_values.values())
        context = {
            'session_values': session_values,
            'all_values_present': all_values_present
        }
        
        return HttpResponse(template.render(context, request))
