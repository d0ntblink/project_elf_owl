import requests

class VulnerableCodeSearch:
    def __init__(self, ip):
        self.base_url = f"http://{ip}/api"

    def get_endpoint(self, endpoint, params=None):
        headers = {'accept': 'application/json'}
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            # beautiful json response
            return response.json()['results'][0]
        else:
            print("Error occurred while getting endpoint:")
            print(response.text)
            return None

    def search_pypi_pkg(self, pkg_name='', namespace='', show_pkg_vuln='', page=1, page_size=1\
        , purl='', qualifiers='', subpath='', type='', version=''):
        endpoint = "packages/"
        params = {
            'name': pkg_name,
            'namespace': namespace,
            'packagerelatedvulnerability__fix': show_pkg_vuln,
            'page': page,
            'page_size': page_size,
            'purl': purl,
            'qualifiers': qualifiers,
            'subpath': subpath,
            'type': type,
            'version': version
        }
        return self.get_endpoint(endpoint=endpoint, params=params)
    
    def get_pypi_lib_lastest_vuln_information(self, lib_name, version=''):
        result = self.search_pypi_pkg(pkg_name=lib_name, type='pypi', version=version)
        if result['affected_by_vulnerabilities'] == 0:
            return "No vulnerabilities found for this library"
        return result['latest_non_vulnerable_version'], result['affected_by_vulnerabilities'], result['fixing_vulnerabilities']

    def search_vulnerabilities(self):
        endpoint = "vulnerabilities/"
        return self.get_endpoint(endpoint=endpoint)

    def search_cpes(self):
        endpoint = "cpes/"
        return self.get_endpoint(endpoint=endpoint)

    def search_aliases(self):
        endpoint = "aliases/"
        return self.get_endpoint(endpoint=endpoint)

if __name__ == "__main__":
    # Example usage:
    search_instance = VulnerableCodeSearch("localhost")

    # Search for PyPI library
    while True:
        library_search_result = search_instance.get_pypi_lib_lastest_vuln_information(input())
        for i in library_search_result:
            for j in i:
                print(j,"\n")

    # # Search for vulnerabilities
    # vulnerabilities_result = search_instance.search_vulnerabilities()
    # print("\nVulnerabilities Search Result:")
    # print(vulnerabilities_result)

    # # Search for CPES
    # cpes_result = search_instance.search_cpes()
    # print("\nCPES Search Result:")
    # print(cpes_result)

    # # Search for aliases
    # aliases_result = search_instance.search_aliases()
    # print("\nAliases Search Result:")
    # print(aliases_result)