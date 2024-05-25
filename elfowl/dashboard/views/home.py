from django.views.generic import TemplateView
from django.http import HttpResponse
from django.template import loader
from dashboard.models import repositories
import logging

class home(TemplateView):
    template_name = 'index.html'
    
    def get(self, request):
        template = loader.get_template(self.template_name)
        repositories_queryset = repositories.objects.all()
        context = {'repositories': repositories_queryset}
        return HttpResponse(template.render(context, request))

class about(TemplateView):
    template_name = 'about.html'

    def get(self, request):
        template = loader.get_template(self.template_name)
        context = {}
        return HttpResponse(template.render(context, request))

class contact(TemplateView):
    template_name = 'contact.html'

    def get(self, request):
        template = loader.get_template(self.template_name)
        context = {}
        return HttpResponse(template.render(context, request))

class documentation(TemplateView):
    template_name = 'documentation.html'

    def get(self, request):
        template = loader.get_template(self.template_name)
        context = {}
        return HttpResponse(template.render(context, request))