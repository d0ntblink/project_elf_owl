import requests
import json
import logging


class VulnerableCodeSearch:
    def __init__(self, vuln_code_host):
        """
        Initialize VulnerableCodeSearch instance.

        Args:
            vuln_code_host (str): host address of the API server.
            dependencies (dict): Dictionary of dependencies with their versions.
        """
        self.logger = logging.getLogger(__name__)
        self.base_url = f"http://{vuln_code_host}/api"
        self.logger.info("VulnerableCodeSearch instance created.")

    def check_dependencies_vulnerabilities(self, dependencies, pkg_type='pypi'):
        """
        Check vulnerabilities for dependencies.
        
        Parameters:
            dependencies (dict): Dictionary of dependencies with their versions.
            pkg_type (str): Type of the package (default is 'pypi').

        Returns:
            dict: Dictionary containing updated dependencies with vulnerability information.
        """
        self.logger.info("Checking dependencies vulnerabilities...")
        updated_dependencies = {}
        if pkg_type == 'pypi':
            for lib_name, requested_version in dependencies.items():
                self.logger.debug(f"Checking {lib_name} version {requested_version} for vulnerabilities.")
                result = self.pypi_operator_action(lib_name, requested_version)
                if result[0] is not None:
                    updated_dependencies[lib_name] = result
        else:
            self.logger.error("Library type not supported.")
            print("Library type not supported.")
        return updated_dependencies

    def get_endpoint(self, endpoint, params=None):
        """
        Get API endpoint.

        Args:
            endpoint (str): Endpoint URL.
            params (dict): Parameters for the request (default is None).

        Returns:
            dict: Response JSON data.
        """
        headers = {'accept': 'application/json'}
        url = f"{self.base_url}/{endpoint}"
        self.logger.debug(f"Requesting endpoint: {url}")
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            # beautiful json response
            return response.json()['results'][0]
        else:
            self.logger.error(f"Error occurred while getting endpoint: {response.text}")
            print("Error occurred while getting endpoint:")
            print(response.text)
            return None

    def search_pkg(self, name='', namespace='', packagerelatedvulnerability__fix='', page=1, page_size=1\
        , purl='', qualifiers='', subpath='', type='', version=''):
        """
        Search for a package.

        Args:
            name (str): Name of the package.
            namespace (str): Namespace of the package.
            packagerelatedvulnerability__fix (str): Vulnerability fix information.
            page (int): Page number for pagination.
            page_size (int): Page size for pagination.
            purl (str): Package URL.
            qualifiers (str): Qualifiers for the search.
            subpath (str): Subpath for the search.
            type (str): Type of the package.
            version (str): Version of the package.

        Returns:
            dict: Response JSON data.
        """
        endpoint = "packages/"
        
        # Build params dict from non-empty params
        params = {
            'name': name,
            'namespace': namespace,
            'packagerelatedvulnerability__fix': packagerelatedvulnerability__fix,
            'page': page,
            'page_size': page_size,
            'purl': purl,
            'qualifiers': qualifiers,
            'subpath': subpath,
            'type': type,
            'version': version
        }
        
        # Filter out empty values
        params = {k: v for k, v in params.items() if v}

        return self.get_endpoint(endpoint=endpoint, params=params)

    def pypi_operator_action(self, lib_name, requested_version):
        """
        Perform action based on PyPI operator.

        Args:
            lib_name (str): Name of the library.
            requested_version (str): Requested version of the library.

        Returns:
            tuple: Tuple containing vulnerability information.
        """
        if requested_version == 'not specified':
            operator, version = ('', '')
        elif '>=' in requested_version:
            operator, version = requested_version.split('>=')
        elif '>' in requested_version:
            operator, version = requested_version.split('>')
        elif '<=' in requested_version:
            operator, version = requested_version.split('<=')
        elif '<' in requested_version:
            operator, version = requested_version.split('<')
        elif '==' in requested_version:
            operator, version = requested_version.split('==')
        else:
            operator, version = (requested_version[0:2], requested_version[2:])
        requested_version_info = self._search_pypi_lib(lib_name, version)
        try:
            if requested_version_info['affected_by_vulnerabilities'] == []:
                return None, None, None, None, None
            else:
                if requested_version_info['latest_non_vulnerable_version'] != "null":
                    upgraded_version_info = self._search_pypi_lib(lib_name, requested_version_info['latest_non_vulnerable_version'])
                    if upgraded_version_info['affected_by_vulnerabilities'] == []:
                        return True,\
                            operator,\
                            requested_version,\
                            upgraded_version_info['version'],\
                            requested_version_info['affected_by_vulnerabilities'],\
                            upgraded_version_info['fixing_vulnerabilities']
                return False, version, None, operator, requested_version_info['affected_by_vulnerabilities'], None
        except Exception as e:
            self.logger.error(f"An error occurred: {e}")
            return None, None, None, None, None
            
    def _search_pypi_lib(self, lib_name, version=''):
        """
        Search for a PyPI library.

        Args:
            lib_name (str): Name of the library.
            version (str): Version of the library.

        Returns:
            dict: Response JSON data.
        """
        try:
            result = self.search_pkg(name=lib_name, type='pypi', version=version)
        except Exception as e:
            self.logger.error(f"An error occurred while searching PyPI package: {e}")
            result = None
        return result
                

if __name__ == "__main__":
    pass