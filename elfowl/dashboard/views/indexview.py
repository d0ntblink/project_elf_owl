from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader

class IndexView(TemplateView):
    template_name = 'index.html'
    
    def get(self, request, *args, **kwargs):
        context = {}
        template = loader.get_template(self.template_name)
        return HttpResponse(template.render(context, request))