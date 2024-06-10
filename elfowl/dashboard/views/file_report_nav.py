from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repository_info_map, repositories
import json
import base64

class file_report_nav(TemplateView):
    report = 'file_report_nav.html'

    def get(self, request, magik_hash, file_name):
        template = loader.get_template(self.report)
        file_information = repository_info_map.objects.filter(
            magik_hash=magik_hash,
            file_name__regex=r'.*{}$'.format(file_name)
        )
        repo_name = repositories.objects.get(magik_hash=magik_hash).repo_name
        with open(f'{file_information[0].file_name}') as f:
            file_content = f.read()
            f.close()
        image_location = file_information[0].cfg_image_relative_location
        ai_security_recommendations = json.loads(file_information[0].ai_security_recommendations_json)['issues']
        ai_bp_recommendations = json.loads(file_information[0].ai_bp_recommendations_json)['recommendations']
        print(ai_bp_recommendations)
        fixed_image_location = image_location.replace("imagescfg", "images/cfg")
        # Read image file as binary and encode in base64
        with open(f'{fixed_image_location}', 'rb') as f:
            image_data = f.read()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
        return HttpResponse(template.render({
            'file_information': file_information,
            'file_name': file_name,
            'file_content': file_content,
            'repo_name': repo_name,
            'magik_hash': magik_hash,
            'image_data': image_base64,
            'ai_security_recommendations': ai_security_recommendations,
            'ai_bp_recommendations': ai_bp_recommendations
        }, request=request))
