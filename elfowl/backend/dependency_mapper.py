import logging
import requests
import time
from packaging.requirements import Requirement
from thread_handler import ThreadManager


class PythonDepandaAnalyzer:
    """
    Analyzes dependencies of a Python program both from code imports and a requirements file.
    It identifies the dependencies and checks for their latest versions on PyPI.
    """

    def __init__(self):
        """
        Initializes the analyzer with Python code and a list of requirements.
        """
        
        self.logger = logging.getLogger("PythonDepandaAnalyzer")
        self.thread_manager = ThreadManager()
        self.checked_dependencies = []
        self.dependencies = {}
        self.logger.info("PythonDepandaAnalyzer initialized")

    def analyze(self, content):
        """
        Conducts the analysis of dependencies by parsing the requirements file and analyzing the code.
        It identifies the latest versions of the dependencies and their transitive dependencies.

        Args:
            content (str): The content of the file to be analyzed.

        Returns:
            dict: A dictionary of dependencies with their corresponding latest versions.
        """

        self.logger.info(f"Starting dependency analysis a requirement file")
        self.content = content
        if content == "":
            self.logger.warning(f"file is empty.")
            return self.dependencies
        # if code_or_requirements == "requirements":
        self._parse_requirements_file()
        # elif code_or_requirements == "code":
        #     self._parse_code_file()
        # else:
        #     self.logger.warning(f"Invalid file type.")
        return self.dependencies

    def _parse_requirements_file(self):
        """
        Parses the requirements file and extracts the dependencies.
        """

        try:
            self.logger.info(f"Parsing requirements for dependencies...")
            self.logger.debug(f"Requirements file: {self.content}")
            requirements_list = self.content.split("\n")
            for requirement in requirements_list:
                requirement = requirement.strip()
                if requirement and not requirement.startswith("#"):
                    parts = requirement.split("==")
                    if len(parts) == 2:
                        package_name, version = parts
                        package_name = package_name.lower()
                        add_version = f"=={version}"
                    else:
                        package_name = parts[0]
                        # latest_version = self._fetch_latest_version(package_name)
                        add_version = "not specified"
                    self.dependencies = self._resolve_all_dependencies(package_name, add_version, resolved=self.dependencies)
            self.logger.debug("Dependencies parsed successfully.")
        except Exception as e:
            self.logger.warning(f"Failed to parse requirements file: {e}")

    def _fetch_latest_version(self, package_name):
        """
        Fetches the latest version of a package from PyPI.

        Args:
            package_name (str): The name of the package.

        Returns:
            str: The latest version of the package.
        """

        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            response = requests.get(url)
            response.raise_for_status()
            latest_version = response.json()['info']['version']
            return latest_version
        except requests.RequestException:
            self.logger.warning(f"Failed to fetch version for {package_name}")
            return None

    def _fetch_depndencies_of_pypi_package(self, package_name):
        """
        Fetches the dependencies of a package from PyPI.

        Args:
            package_name (str): The name of the package.

        Returns:
            dict: A dictionary of dependencies with their corresponding versions.
        """

        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            raw_dependencies = data['info'].get('requires_dist', [])
            dependencies = {}

            if raw_dependencies is not None:
                for dep in raw_dependencies:
                    if dep:
                        requirement = Requirement(dep)
                        if requirement.specifier:
                            specifier = next(iter(requirement.specifier), None)
                            dependencies[requirement.name.lower()] = f"{specifier.operator}{specifier.version}"

            return dependencies
        except requests.RequestException:
            self.logger.warning(f"Failed to fetch dependencies for {package_name}")
            return {}

    def _resolve_all_dependencies(self, package_name, version, resolved):
        """
        Resolves all the dependencies of a package recursively.

        Args:
            package_name (str): The name of the package.
            version (str): The version of the package.
            resolved (dict): A dictionary of resolved dependencies.

        Returns:
            dict: A dictionary of resolved dependencies.
        """

        updated_resolved = resolved
        updated_resolved[package_name] = version
        sub_dependencies = {}
        if package_name.lower() not in self.checked_dependencies:
            sub_dependencies = self._fetch_depndencies_of_pypi_package(package_name)
            self.checked_dependencies.append(package_name.lower())
        updated_resolved.update(sub_dependencies)
        for sub_package, sub_version in sub_dependencies.items():
            if sub_package.lower() not in self.checked_dependencies:
                updated_resolved = self._resolve_all_dependencies(sub_package, sub_version, resolved=updated_resolved)
            else:
                pass
        return updated_resolved


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    analyzer = PythonDepandaAnalyzer()
    with open("./test_requirement") as f:
        content = f.read()
        f.close()
    # calculate time taken to analyze the file
    current_time = time.time()
    dependencies = analyzer.analyze(content)
    print(f"Time taken to analyze: {time.time() - current_time}")
    print(dependencies)
    print(analyzer.checked_dependencies)
    print(analyzer.dependencies)