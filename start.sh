#!/bin/sh

IMPORTERS="
NVD=vulnerabilities.importers.nvd.NVDImporter
GITHUB=vulnerabilities.importers.github.GitHubAPIImporter
GITLAB=vulnerabilities.importers.gitlab.GitLabAPIImporter
NPM=vulnerabilities.importers.npm.NpmImporter
PYPA=vulnerabilities.importers.pypa.PyPaImporter
NGINX=vulnerabilities.importers.nginx.NginxImporter
PYSEC=vulnerabilities.importers.pysec.PyPIImporter
ALPINE=vulnerabilities.importers.alpine_linux.AlpineImporter
OPENSSL=vulnerabilities.importers.openssl.OpensslImporter
REDHAT=vulnerabilities.importers.redhat.RedhatImporter
DEBIAN=vulnerabilities.importers.debian.DebianImporter
POSTGRESQL=vulnerabilities.importers.postgresql.PostgreSQLImporter
ARCHLINUX=vulnerabilities.importers.archlinux.ArchlinuxImporter
UBUNTU=vulnerabilities.importers.ubuntu.UbuntuImporter
DEBIAN_OVAL=vulnerabilities.importers.debian_oval.DebianOvalImporter
RETIRE_DOTNET=vulnerabilities.importers.retiredotnet.RetireDotnetImporter
APACHE_HTTPD=vulnerabilities.importers.apache_httpd.ApacheHTTPDImporter
MOZILLA=vulnerabilities.importers.mozilla.MozillaImporter
GENTOO=vulnerabilities.importers.gentoo.GentooImporter
ISTIO=vulnerabilities.importers.istio.IstioImporter
PROJECT_KB_MSR=vulnerabilities.importers.project_kb_msr2019.ProjectKBMSRImporter
SUSE_SEVERITY_SCORE=vulnerabilities.importers.suse_scores.SUSESeverityScoreImporter
ELIXIR_SECURITY=vulnerabilities.importers.elixir_security.ElixirSecurityImporter
APACHE_TOMCAT=vulnerabilities.importers.apache_tomcat.ApacheTomcatImporter
XEN=vulnerabilities.importers.xen.XenImporter
UBUNTU_USN=vulnerabilities.importers.ubuntu_usn.UbuntuUSNImporter
FIREYE=vulnerabilities.importers.fireeye.FireyeImporter
APACHE_KAFKA=vulnerabilities.importers.apache_kafka.ApacheKafkaImporter
OSS_FUZZ=vulnerabilities.importers.oss_fuzz.OSSFuzzImporter
RUBY=vulnerabilities.importers.ruby.RubyImporter
GITHUB_OSV=vulnerabilities.importers.github_osv.GithubOSVImporter
"

IMPORT_COMMAND="python manage.py import"

for IMPORTER in $IMPORTERS; do
  VAR=$(echo "$IMPORTER" | cut -d '=' -f 1)
  IMPORTER_CLASS=$(echo "$IMPORTER" | cut -d '=' -f 2)
  if [ "$(eval echo \$"$VAR")" = "true" ]; then
    IMPORT_COMMAND="$IMPORT_COMMAND $IMPORTER_CLASS"
  fi
done

./manage.py migrate
./manage.py collectstatic --no-input --verbosity 0 --clear

exec gunicorn vulnerablecode.wsgi:application -u nobody -g nogroup --bind :8000 --timeout 600 --workers 8

$IMPORT_COMMAND
python manage.py improve --all