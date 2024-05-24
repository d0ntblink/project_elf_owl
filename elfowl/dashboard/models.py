from django.db import models

class repositories(models.Model):
    repo_name = models.TextField(null=False)
    repo_origin = models.TextField()
    repo_branch = models.TextField()
    repo_location = models.TextField(unique=True)
    added_by = models.TextField()
    added_on = models.DateTimeField(auto_now_add=True)
    last_synced_by = models.TextField(null=True)
    last_synced_on = models.DateTimeField(null=True)
    last_commit_msg = models.TextField(null=True)
    last_commit_short_hash = models.TextField(null=True)
    magik_hash = models.TextField(unique=True)

class repository_info_map(models.Model):
    file_name = models.TextField()
    dataflow_json = models.TextField(null=True)
    owasp_top10_json = models.TextField(null=True)
    ai_bp_recommendations_json = models.TextField(null=True)
    ai_security_recommendations_json = models.TextField(null=True)
    cfg_image_relative_location = models.TextField(null=True)
    secrets_found_json = models.TextField(null=True)
    magik_hash = models.TextField(null=True)

class repository_dependency_map(models.Model):
    dependencies_json = models.TextField()
    dependencies_cve_vuln_found_json = models.TextField(null=True)
    magik_hash = models.TextField(unique=True)
