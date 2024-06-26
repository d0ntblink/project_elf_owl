#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase

from vulnerabilities import severity_systems


class TestMigrations(TestCase):
    @property
    def app(self):
        return apps.get_containing_app_config(self.app_name).name

    app_name = None
    migrate_from = None
    migrate_to = None

    def setUp(self):
        assert (
            self.migrate_from and self.migrate_to
        ), "TestCase '{}' must define migrate_from and migrate_to properties".format(
            type(self).__name__
        )
        self.migrate_from = [(self.app, self.migrate_from)]
        self.migrate_to = [(self.app, self.migrate_to)]
        executor = MigrationExecutor(connection)
        old_apps = executor.loader.project_state(self.migrate_from).apps

        # # Reverse to the original migration
        executor.migrate(self.migrate_from)

        self.setUpBeforeMigration(old_apps)

        # Run the migration to test
        executor = MigrationExecutor(connection)
        executor.loader.build_graph()  # reload.
        executor.migrate(self.migrate_to)

        self.apps = executor.loader.project_state(self.migrate_to).apps

    def setUpBeforeMigration(self, apps):
        pass


class DuplicateSeverityTestCase(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0013_auto_20220503_0941"
    migrate_to = "0014_remove_duplicate_severities"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        Severities = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        Vulnerability = apps.get_model("vulnerabilities", "Vulnerability")

        reference = VulnerabilityReference.objects.create(
            reference_id="CVE-TEST", url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-TEST"
        )
        self.reference = reference
        vulnerability1 = Vulnerability(vulnerability_id=1, summary="test-1")
        vulnerability1.save()
        vulnerability2 = Vulnerability(vulnerability_id=2, summary="test-2")
        vulnerability2.save()
        vulnerability3 = Vulnerability(vulnerability_id=3, summary="test-3")
        vulnerability3.save()
        Severities.objects.update_or_create(
            vulnerability=vulnerability1,
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )
        Severities.objects.update_or_create(
            vulnerability=vulnerability2,
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )
        Severities.objects.update_or_create(
            vulnerability=vulnerability3,
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )

    def test_remove_duplicate_rows(self):
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        assert len(VulnerabilitySeverity.objects.filter(reference=self.reference.id)) == 1


class DropVulnerabilityFromSeverityTestCase(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0014_remove_duplicate_severities"
    migrate_to = "0015_alter_vulnerabilityseverity_unique_together_and_more"

    def test_dropping_vulnerability_from_severity(self):
        # using get_model to avoid circular import
        VulnerabilityReference = self.apps.get_model("vulnerabilities", "VulnerabilityReference")
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")

        reference = VulnerabilityReference.objects.create(
            reference_id="CVE-TEST", url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-TEST"
        )
        VulnerabilitySeverity.objects.update_or_create(
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )


class UpdateCPEURL(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0015_alter_vulnerabilityseverity_unique_together_and_more"
    migrate_to = "0016_update_cpe_url"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")

        reference = VulnerabilityReference.objects.create(
            reference_id="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", url=""
        )
        reference.save()
        self.reference = reference

    def test_cpe_url_update(self):
        # using get_model to avoid circular import
        VulnerabilityReference = self.apps.get_model("vulnerabilities", "VulnerabilityReference")
        ref = VulnerabilityReference.objects.get(reference_id=self.reference.reference_id)
        assert (
            ref.url
            == "https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query=cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        )


class TestCvssVectorMigrationToScoringElementComputeNewScores(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0031_vulnerabilityseverity_scoring_elements"
    migrate_to = "0032_vulnerabilityseverity_merge_cvss_score_and_vector"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilitySeverity = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        reference = VulnerabilityReference.objects.create(
            id=1, reference_id="fake-reference_id", url="fake-url"
        )
        reference.save()
        self.reference = reference
        self.severities = [
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv2_vector",
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3_vector",
                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3.1_vector",
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv2_vector",
                value="",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="generic_textual",
                value="Low",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="rhbs",
                value="medium",
                reference_id=1,
            ),
        ]
        for severity in self.severities:
            severity.save()

    def test_compute_cvss(self):
        # using get_model to avoid circular import
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        severities = list(
            VulnerabilitySeverity.objects.values(
                "reference_id", "scoring_system", "value", "scoring_elements"
            ).all()
        )
        expected = [
            {
                "reference_id": 1,
                "scoring_system": "cvssv2",
                "value": "7.5",
                "scoring_elements": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            },
            {
                "reference_id": 1,
                "scoring_system": "cvssv2",
                "value": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "scoring_elements": None,
            },
            {
                "reference_id": 1,
                "scoring_system": "cvssv3",
                "value": "7.5",
                "scoring_elements": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
            {
                "reference_id": 1,
                "scoring_system": "cvssv3.1",
                "value": "9.8",
                "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            {
                "reference_id": 1,
                "scoring_system": "generic_textual",
                "value": "Low",
                "scoring_elements": None,
            },
            {
                "reference_id": 1,
                "scoring_system": "rhbs",
                "value": "medium",
                "scoring_elements": None,
            },
        ]
        assert severities == expected


class TestCvssVectorMigrationToScoringElementMergeRows(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0031_vulnerabilityseverity_scoring_elements"
    migrate_to = "0032_vulnerabilityseverity_merge_cvss_score_and_vector"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilitySeverity = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        self.reference_list = [
            VulnerabilityReference.objects.create(
                id=1,
                reference_id="fake-reference_id1",
                url="fake-url1",
            ),
            VulnerabilityReference.objects.create(
                id=2,
                reference_id="fake-reference_id2",
                url="fake-url2",
            ),
            VulnerabilityReference.objects.create(
                id=3,
                reference_id="fake-reference_id3",
                url="fake-url3",
            ),
            VulnerabilityReference.objects.create(
                id=4,
                reference_id="fake-reference_id4",
                url="fake-url4",
            ),
            VulnerabilityReference.objects.create(
                id=5,
                reference_id="fake-reference_id5",
                url="fake-url5",
            ),
        ]

        for reference in self.reference_list:
            reference.save()

        self.severities = [
            # test severity_cvss2
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="7.5",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv2_vector",
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                reference_id=1,
            ),
            # test severity_cvss3
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3.identifier,
                value="7.5",
                reference_id=2,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3_vector",
                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                reference_id=2,
            ),
            # test severity_cvss3_1
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV31.identifier,
                value="9.8",
                reference_id=3,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3.1_vector",
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reference_id=3,
            ),
            # test all type of severities for the same reference_id 4
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="7.5",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv2_vector",
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3.identifier,
                value="7.5",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3_vector",
                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV31.identifier,
                value="9.8",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3.1_vector",
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="generic_textual",
                value="Low",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="rhbs",
                value="medium",
                reference_id=4,
            ),
            # solo cases
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3.identifier,
                value="8",
                reference_id=5,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv3.1_vector",
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                # value="9.8",
                reference_id=5,
            ),
        ]

        for severity in self.severities:
            severity.save()

    def test_merge_rows(self):
        # using get_model to avoid circular import
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")

        severities = list(
            VulnerabilitySeverity.objects.values(
                "reference_id",
                "scoring_system",
                "value",
                "scoring_elements",
            ).all()
        )
        expected = [
            {
                "reference_id": 1,
                "scoring_system": "cvssv2",
                "value": "7.5",
                "scoring_elements": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            },
            {
                "reference_id": 2,
                "scoring_system": "cvssv3",
                "value": "7.5",
                "scoring_elements": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
            {
                "reference_id": 3,
                "scoring_system": "cvssv3.1",
                "value": "9.8",
                "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            {
                "reference_id": 4,
                "scoring_system": "cvssv2",
                "value": "7.5",
                "scoring_elements": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            },
            {
                "reference_id": 4,
                "scoring_system": "cvssv3",
                "value": "7.5",
                "scoring_elements": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
            {
                "reference_id": 4,
                "scoring_system": "cvssv3.1",
                "value": "9.8",
                "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            {
                "reference_id": 4,
                "scoring_system": "generic_textual",
                "value": "Low",
                "scoring_elements": None,
            },
            {
                "reference_id": 4,
                "scoring_system": "rhbs",
                "value": "medium",
                "scoring_elements": None,
            },
            {
                "reference_id": 5,
                "scoring_system": "cvssv3",
                "value": "8",
                "scoring_elements": None,
            },
            {
                "reference_id": 5,
                "scoring_system": "cvssv3.1",
                "value": "9.8",
                "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        ]
        assert severities == expected


class TestCvssVectorMigrationToScoringElementMergeRowsWithDupes(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0031_vulnerabilityseverity_scoring_elements"
    migrate_to = "0032_vulnerabilityseverity_merge_cvss_score_and_vector"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilitySeverity = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        self.v1 = VulnerabilityReference.objects.create(
            id=1,
            reference_id="fake-reference_id1",
            url="fake-url1",
        )
        self.v1.save()

        self.severities = [
            # no matching vector: should stay as is
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="8.3",
                reference_id=1,
            ),
            # no matching score: score should be computed
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv2_vector",
                value="AV:N/AC:H/Au:N/C:P/I:P/A:P",
                reference_id=1,
            ),
            # pair of score/vector: should be merged
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="7.5",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="cvssv2_vector",
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                reference_id=1,
            ),
        ]

        for severity in self.severities:
            severity.save()

    def test_merge_rows(self):
        # using get_model to avoid circular import
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")

        severities = list(
            VulnerabilitySeverity.objects.values(
                "reference_id",
                "scoring_system",
                "value",
                "scoring_elements",
            ).all()
        )

        expected = [
            {
                "reference_id": 1,
                "scoring_elements": "AV:N/AC:H/Au:N/C:P/I:P/A:P",
                "scoring_system": "cvssv2",
                "value": "5.1",
            },
            {
                "reference_id": 1,
                "scoring_elements": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "scoring_system": "cvssv2",
                "value": "7.5",
            },
            {
                "reference_id": 1,
                "scoring_elements": None,
                "scoring_system": "cvssv2",
                "value": "8.3",
            },
        ]

        assert severities == expected


class RemoveCorrupteAdvisories(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0037_advisory_weaknesses_weakness"
    migrate_to = "0038_remove_corrupted_advisories_with_incorrect_refs_and_severity"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        Advisory = apps.get_model("vulnerabilities", "Advisory")

        corrupted_advisory = Advisory.objects.create(
            aliases=["CVE-2020-1234"],
            summary="Corrupted advisory",
            references=[
                {
                    "reference_id": "cpe:2.3:a:f5:nginx:1.16.1:*:*:*:*:*:*:*",
                    "url": "",
                    "severity": [
                        {
                            "scoring_system": "cvssv3_vector",
                            "value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                }
            ],
            date_collected="2020-01-01",
            date_published="2020-01-01",
        )
        corrupted_advisory.save()

    def test_removal_of_corrupted_advisory(self):
        # using get_model to avoid circular import
        Advisory = self.apps.get_model("vulnerabilities", "Advisory")
        Advisory.objects.all().count() == 0


class RemoveVulnerabilitiesWithEmptyAliases(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0040_remove_advisory_date_improved_advisory_date_imported"
    migrate_to = "0041_remove_vulns_with_empty_aliases"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        Vulnerability = apps.get_model("vulnerabilities", "Vulnerability")
        Alias = apps.get_model("vulnerabilities", "Alias")

        vuln = Vulnerability.objects.create(
            summary="Corrupted vuln",
        )
        vuln.save()
        vuln = Vulnerability.objects.create(
            summary="vuln",
        )
        vuln.save()
        Alias.objects.create(alias="CVE-123", vulnerability=vuln)

    def test_removal_of_corrupted_vulns(self):
        # using get_model to avoid circular import
        Vulnerability = self.apps.get_model("vulnerabilities", "Vulnerability")
        Vulnerability.objects.all().count() == 1


class TestRemoveDupedPurlsWithSameQualifiers(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0043_alter_advisory_unique_together_advisory_url_and_more"
    migrate_to = "0045_remove_duplicated_purls_with_same_qualifiers"

    def setUpBeforeMigration(self, apps):
        Package = apps.get_model("vulnerabilities", "Package")
        self.pkg1 = Package.objects.create(type="nginx", name="nginx", qualifiers={"os": "windows"})

        pkg2 = Package.objects.create(type="nginx", name="nginx", qualifiers="os=windows")

    def test_removal_of_duped_purls(self):
        Package = apps.get_model("vulnerabilities", "Package")
        assert Package.objects.count() == 1


class TestRemoveDupedChangeLogWithSameData(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0054_alter_packagechangelog_software_version_and_more"
    migrate_to = "0055_remove_changelogs_with_same_data_different_software_version"

    def setUpBeforeMigration(self, apps):
        PackageChangeLog = apps.get_model("vulnerabilities", "PackageChangeLog")
        VulnerabilityChangeLog = apps.get_model("vulnerabilities", "VulnerabilityChangeLog")
        Package = apps.get_model("vulnerabilities", "Package")
        Vulnerability = apps.get_model("vulnerabilities", "Vulnerability")
        pkg1 = Package.objects.create(type="nginx", name="nginx", qualifiers={"os": "windows"})
        vuln = Vulnerability.objects.create(summary="NEW")
        PackageChangeLog.objects.create(
            actor_name="Nginx",
            action_type=1,
            source_url="test",
            software_version="1",
            package=pkg1,
            related_vulnerability=vuln,
        )
        PackageChangeLog.objects.create(
            actor_name="Nginx",
            action_type=1,
            source_url="test",
            software_version="2",
            package=pkg1,
            related_vulnerability=vuln,
        )
        VulnerabilityChangeLog.objects.create(
            actor_name="Nginx",
            action_type=1,
            source_url="test",
            software_version="2",
            vulnerability=vuln,
        )
        VulnerabilityChangeLog.objects.create(
            actor_name="Nginx",
            action_type=1,
            source_url="test",
            software_version="1",
            vulnerability=vuln,
        )

    def test_removal_of_changelog(self):
        PackageChangeLog = apps.get_model("vulnerabilities", "PackageChangeLog")
        VulnerabilityChangeLog = apps.get_model("vulnerabilities", "VulnerabilityChangeLog")
        assert PackageChangeLog.objects.all().count() == 1
        assert VulnerabilityChangeLog.objects.all().count() == 1
