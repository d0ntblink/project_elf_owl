from django.views.generic import TemplateView
from django.http import HttpResponse
from django.shortcuts import render
from django.views import View

class SettingsView(TemplateView):
    template_name = 'settings.html'

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(request)
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        api_value = request.POST.get('api_value')
        org_value = request.POST.get('org_value')
        model_value = request.POST.get('model_value')

        if api_value:
            request.session['apikey'] = api_value
        if org_value:
            request.session['orgid'] = org_value
        if model_value:
            request.session['model'] = model_value

        context = self.get_context_data(request)
        return self.render_to_response(context)

    def get_context_data(self, request):
        context = super().get_context_data()
        context['session_values'] = {key: request.session.get(key) for key in request.session.keys()}
        context['available_models'] = ['gpt-4o',
                                       'gpt-4-1106-preview',
                                       'gpt-4-turbo',
                                       'gpt-3.5-turbo-1106',
                                       'gpt-3.5-turbo']
        return context

class GetSessionValueView(View):
    def get(self, request, *args, **kwargs):
        key = kwargs.get('key')
        value = request.session.get(key, 'No value set')
        return HttpResponse(f"Session value for {key} is: {value}")

class DeleteSessionValueView(View):
    def get(self, request, *args, **kwargs):
        key = kwargs.get('key')
        if key in request.session:
            del request.session[key]
        return HttpResponse(f"Session value for {key} deleted")
