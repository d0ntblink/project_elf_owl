from django.contrib import admin
from dashboard.models import repositories, repository_dependency_map, repository_info_map
# Register your models here.

admin.site.register(repository_info_map)
admin.site.register(repository_dependency_map)
admin.site.register(repositories)