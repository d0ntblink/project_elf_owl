import subprocess
import logging
from hashlib import md5

class GitHandler:
    def __init__(self, target_directory):
        self.logger = logging.getLogger(__name__)
        self.target_directory = target_directory

    def git_clone(self, repo_origin, repo_branch):
        """
        Clones a single branch of a Git repository to a specified directory.

        :param repo_origin: Origin URL of the Git repository.
        :param repo_branch: Branch of the repository to clone.
        :return: True if cloning is successful, False otherwise.
        """
        target_directory = self._directory_path_from_repo_origin(repo_origin, repo_branch)
        repo_name = self._repo_name_from_repo_origin(repo_origin)
        try:
            subprocess.run(['git', 'clone', '--single-branch', '--branch', repo_branch, repo_origin, target_directory], check=True)
            
            self.logger.info(f"{repo_name}@{repo_branch} repository cloned successfully to {target_directory}.")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error cloning repository: {e}")
            return False

    def git_fetch_and_pull(self, repo_directory):
        """
        Fetches and pulls updates for the repository in the specified directory.

        :param repo_directory: Directory of the Git repository.
        :return: True if fetch and pull are successful, False otherwise.
        """
        try:
            subprocess.run(['git', 'fetch'], cwd=repo_directory, check=True)
            subprocess.run(['git', 'pull'], cwd=repo_directory, check=True)
            self.logger.info("Fetch and pull successful.")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error fetching and pulling updates: {e}")
            return False

    def confirm_remote_and_branch_exist(self, repo_origin, repo_branch):
        """
        Confirms if the remote and branch exist for a Git repository.

        :param repo_origin: Origin URL of the Git repository.
        :param repo_branch: Branch to confirm existence.
        :return: True if both remote and branch exist, False otherwise.
        """
        try:
            subprocess.run(['git', 'ls-remote', '--exit-code', repo_origin, repo_branch], check=True)
            self.logger.info(f"Remote '{repo_origin}' and branch '{repo_branch}' exist.")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error confirming remote and branch existence: {e}")
            return False

    def get_remote_branches(self, repo_origin):
        """
        Retrieves the list of branches for a Git repository.

        :param repo_origin: Origin URL of the Git repository.
        :return: List of branches.
        """
        try:
            branches = subprocess.check_output(['git', 'ls-remote', '--heads', repo_origin], universal_newlines=True).split('\n')
            branches = [branch.split('\t')[1].split('refs/heads/')[1] for branch in branches if branch]
            self.logger.info(f"Branches retrieved successfully: {branches}")
            return branches
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error retrieving branches: {e}")
            return None

    def get_last_commit_info(self, repo_directory):
        """
        Retrieves information about the last commit on a Git branch.

        :param repo_directory: Directory of the Git repository.
        :return: Last commit message and short hash.
        """
        try:
            commit_msg = subprocess.check_output(['git', 'log', '-1', '--pretty=%B'], cwd=repo_directory, universal_newlines=True).strip()
            short_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=repo_directory, universal_newlines=True).strip()
            self.logger.info("Last commit information retrieved successfully.")
            return commit_msg, short_hash
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error retrieving last commit information: {e}")
            return None, None
    
    def _directory_path_from_repo_origin(self, repo_origin, repo_branch):
        """
        Generates a directory name from a Git repository origin URL.

        :param repo_origin: Origin URL of the Git repository.
        :return: Directory path.
        """
        repo_name = self._repo_name_from_repo_origin(repo_origin)
        target_directory = f"{self.target_directory}/{md5((''.join(map(str, [repo_name, repo_branch]))).encode()).hexdigest()}"
        return target_directory
    
    def _repo_name_from_repo_origin(self, repo_origin):
        """
        Generates a directory name from a Git repository origin URL.

        :param repo_origin: Origin URL of the Git repository.
        :return: Directory name.
        """
        repo_name = repo_origin.split('/')[-1].split('.')[0]
        return repo_name


class FileManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def list_code_files(self, directory_path, file_extension_list = ['.py']):
        """
        Lists all code files in a directory and its subdirectories.

        :param directory_path: Path of the directory to search.
        :param file_extension_list: List of file extensions to search for. Default is ['.py'].
        :return: List of code files.
        """
        for ext in file_extension_list:
            if ext[0] != '.':
                ext = '.' + ext
            try:
                find_command = ['find', directory_path, '-type', 'f', '-name', f'*{ext}']
                self.logger.debug(f"Running find command: {find_command}")
                code_files = subprocess.check_output(find_command, universal_newlines=True).split('\n')
                code_files = [file for file in code_files if file]
                if len(code_files) > 0:
                    self.logger.info(f"Code files listed successfully: {code_files}")
                    return code_files
                else :
                    self.logger.warning(f"No code files found in {directory_path}")
                    return None
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error listing code files: {e}")
                return None

    def find_requirements_file(self, directory_path):
        """
        Finds a requirements.txt file in a directory and its subdirectories.

        :param directory_path: Path of the directory to search.
        :return: Path of the requirements.txt file if found, None otherwise.
        """
        try:
            find_command = ['find', directory_path, '-type', 'f', '-iname', 'requirements.txt']
            self.logger.debug(f"Running find command: {find_command}")
            requirements_file = subprocess.check_output(find_command, universal_newlines=True).strip()
            if requirements_file:
                self.logger.info(f"Requirements file found: {requirements_file}")
                return requirements_file
            else:
                self.logger.warning(f"No requirements file found in {directory_path}")
                return None
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error finding requirements file: {e}")
            return None

    def remove_directory(self, directory_path):
        """
        Removes a directory and its contents.

        :param directory_path: Path of the directory to remove.
        :return: True if removal is successful, False otherwise.
        """
        try:
            subprocess.run(['rm', '-rf', directory_path], check=True)
            self.logger.info(f"Directory {directory_path} removed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error removing directory: {e}")
            return False

    def remove_file(self, file_path):
        """
        Removes a file.

        :param file_path: Path of the file to remove.
        :return: True if removal is successful, False otherwise.
        """
        try:
            subprocess.run(['rm', '-f', file_path], check=True)
            self.logger.info(f"File {file_path} removed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error removing file: {e}")
            return False    


if __name__ == "__main__":
    from db_handler import DatabaseManager
    from code_analyzer import PythonASTAnalyzer, PythonDataFlow, CodeCFGAnalyzer, PythonDepandaAnalyzer
    from openai_handler import OpenAIClient
    from cwe_cve_handler import VulnerableCodeSearch
    from secret_finder import SecretFinder  
    from json import dumps
    from test_secrets import orgid, apikey
    logging.basicConfig(level=logging.DEBUG)
    git_handler = GitHandler("/elfowl/data/downloads")
    db_manager = DatabaseManager("/elfowl/data/database/git_handler_test.sqlite")
    file_manager = FileManager()
    ast_analyzer = PythonASTAnalyzer()
    depen_analyzer = PythonDepandaAnalyzer()
    flow_analyzer = PythonDataFlow()
    cfg_analyzer = CodeCFGAnalyzer()
    depen_vuln_search = VulnerableCodeSearch(ip="nginx", lib_type="pypi")
    model = "gpt-3.5-turbo-0125"
    openai_client = OpenAIClient(api_key=apikey, organization=orgid)
    db_manager.create_tables()
    repo_branch = "master"
    repo_origin = "https://github.com/gouthambs/Flask-Blogging.git"
    branches = git_handler.get_remote_branches(repo_origin)
    if git_handler.confirm_remote_and_branch_exist(repo_origin, repo_branch):
        print("Remote and branch exist.")
        git_handler.git_clone(repo_origin, repo_branch)
        repo_name = git_handler._repo_name_from_repo_origin(repo_origin)
        print(repo_name)
        repo_location = git_handler._directory_path_from_repo_origin(repo_origin, repo_branch)
        secret_finder = SecretFinder(config_file='truffles_config.yml', repo_location=repo_location)
        secrets_found = secret_finder.find_secrets()
        last_commit_msg, last_commit_hash = git_handler.get_last_commit_info(repo_location)
        print(last_commit_msg, last_commit_hash)
        magik_hash, success = db_manager.add_repository(repo_name=repo_name,repo_origin=repo_origin, repo_branch=repo_branch,\
            added_by="test_user", repo_location=repo_location,\
            last_commit_msg=last_commit_msg, last_commit_short_hash=last_commit_hash)
        if success == False:
            print("Error adding repository")
            exit()
        print(magik_hash)
        code_file_list = file_manager.list_code_files(repo_location)
        requirements_file = file_manager.find_requirements_file(repo_location)
        print(requirements_file, code_file_list)
        with open(requirements_file) as f:
            content = f.read()
            f.close()
        depen_analyzer.analyze(content=content)
        if code_file_list:
            for code_file in code_file_list:
                with open(code_file) as f:
                    content = f.read()
                    f.close()
                owasp_reco = ast_analyzer.analyze(code=content)
                variable_flow = flow_analyzer.analyze(code=content)
                cfg_image_location = cfg_analyzer.generate_cfg(code=content)
                sec_json, total_tokens = openai_client.generate_response(
                    task_type="security",
                    model=model,
                    temperature=0,
                    frequency_penalty=0,
                    presence_penalty=0,
                    code_context=content,
                    assistant_context=owasp_reco
                )
                bp_json, total_tokens = openai_client.generate_response(
                    task_type="best_practices",
                    model=model,
                    temperature=0,
                    frequency_penalty=0,
                    presence_penalty=0,
                    code_context=content
                )
                db_manager.add_information(file_name=code_file, dataflow_json=dumps(variable_flow), owasp_top10_json=dumps(owasp_reco), ai_bp_recommendations_json=bp_json,\
                    ai_security_recommendations_json=sec_json, cfg_image_relative_location=cfg_image_location, magik_hash=magik_hash)
            db_manager.add_dependencies(dependencies_json=dumps(depen_analyzer.dependencies),\
                dependencies_cve_vuln_found_json=dumps(depen_vuln_search.check_dependencies_vulnerabilities(depen_analyzer.dependencies)),\
                magik_hash=magik_hash)
            
            db_manager.add_secrets_found(secrets_found_json=dumps(secrets_found), magik_hash=magik_hash)
    # delete the database and clean up
    print(f"rm -rf {db_manager._retrieve_fields(field_name="repo_location",table_name="Repository",\
        where_clauses=["repo_name"], where_values=[repo_name])} && rm -rf ./data/database/git_handler_test.sqlite && rm -rf ./data/images/*")
