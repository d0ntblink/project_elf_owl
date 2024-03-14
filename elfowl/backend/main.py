from db_handler import DatabaseManager
from code_analyzer import PythonASTAnalyzer, PythonDataFlow, CodeCFGAnalyzer, PythonDepandaAnalyzer
from openai_handler import OpenAIClient
from cwe_cve_handler import VulnerableCodeSearch
from secret_finder import SecretFinder
from git_handler import GitHandler
from file_manager import FileManager
from threading_handler import ThreadHandler
from json import dumps, loads
import logging

class runDashboard:
    
    def __init__(self, db_file, repo_locations, image_store_location, openai_model,\
        api_key, org_id, vuln_code_host, truffles_config_file):
        self.logger = logging.getLogger(__name__)
        self.gitHandler = GitHandler(repo_locations)
        self.vulnCodeSearch = VulnerableCodeSearch(vuln_code_host=vuln_code_host)
        self.fileManager = FileManager()
        self.databaseManager = DatabaseManager(db_file)
        self.openaiClient = OpenAIClient(api_key=api_key, org_id=org_id)
        # self.threadHandler = ThreadHandler()
        self.secretFinder = SecretFinder(config_file=truffles_config_file)
        self.cfgAnalyzer = CodeCFGAnalyzer(save_image_location=image_store_location)
        self.image_store_location = image_store_location
        self.repo_locations = repo_locations
        self.db_location = db_file
        self.openai_model = openai_model
        self.magik_hash = ""
        
    def setup_tables(self):
        self.databaseManager.create_tables()
        
    def new_repo_sequence(self, repo_origin, repo_branch):
        self.logger.info(f"Repository analysis started for {repo_origin} and branch {repo_branch}")
        branches = self.get_remote_branches(repo_origin)
        if branches is None:
            self.logger.error("No branches found")
            return None
        repo_location, repo_name = self.download_repositories(repo_origin, repo_branch)
        if repo_location is None:
            self.logger.error("Error downloading repository")
            return None
        magik_hash = self.add_repository(repo_origin, repo_branch, repo_location, repo_name)
        if magik_hash is None:
            self.logger.error("Error adding repository")
            return None
        self.analyze_repo(repo_location, magik_hash)
        self.logger.info(f"Repository analysis completed for {repo_origin} and branch {repo_branch}, magik hash: {magik_hash}")
        return magik_hash
        
    def get_remote_branches(self, repo_origin):
        try:
            branches = self.gitHandler.get_remote_branches(repo_origin)
            self.logger.info(f"Branches: {branches}")
            return branches
        except Exception as e:
            self.logger.error(f"Remote doesn't exist or is not accessible: {e}")
            return None
    
    def download_repositories(self, repo_origin, repo_branch):
        if self.gitHandler.confirm_remote_and_branch_exist(repo_origin, repo_branch):
            self.logger.info("Remote and branch exist.")
            repo_name = self.gitHandler._repo_name_from_repo_origin(repo_origin)
            repo_location = self.gitHandler.git_clone(repo_origin, repo_branch)
            self.logger.info(f"Repository {repo_name} cloned to {repo_location}")
            return repo_location, repo_name
        else:
            self.logger.error("Remote and branch do not exist.")
            return None
        
    def add_repository(self, repo_origin, repo_branch, repo_location, repo_name):
        last_commit_msg, last_commit_hash = self.gitHandler.get_last_commit_info(repo_location)
        self.logger.debug(f"Last commit message: {last_commit_msg}, Last commit hash: {last_commit_hash}")
        magik_hash, success = self.databaseManager.add_repository(repo_name=repo_name,repo_origin=repo_origin, repo_branch=repo_branch,\
            added_by="test_user", repo_location=repo_location,\
            last_commit_msg=last_commit_msg, last_commit_short_hash=last_commit_hash)
        self.magik_hash = magik_hash
        if success == False:
            self.logger.error("Error adding repository")
            return None
        self.logger.info(f"Repository added with magik hash: {magik_hash}")
        return magik_hash

    def analyze_repo(self, repo_location, magik_hash):
        self.depenAnalyzer = PythonDepandaAnalyzer()
        self.astAnalyzer = PythonASTAnalyzer()
        self.flowAnalyzer = PythonDataFlow()
        self.logger.info(f"Repo analyzer initialized for {repo_location}")
        code_file_list = self.fileManager.list_code_files(repo_location)
        self.logger.debug(f"Code files found: {code_file_list}")
        requirements_file_list = self.fileManager.find_requirements_file(repo_location)
        self.logger.debug(f"Requirements files found: {requirements_file_list}")
        dependencies_found = self._analyze_requirements(requirements_file_list)
        vuln_dependeincies = self.vulnCodeSearch.check_dependencies_vulnerabilities(dependencies_found, pkg_type="pypi")
        self.databaseManager.add_dependencies(dependencies_json=dumps(dependencies_found),\
            dependencies_cve_vuln_found_json=dumps(vuln_dependeincies),\
            magik_hash=magik_hash)
        for code_file in code_file_list:
            self.logger.info(f"Analyzing code file: {code_file}")
            with open(code_file) as f:
                content = f.read()
                f.close()
            if len(content) < 1000:
                continue
            else:
                secrets_found = self.secretFinder.find_secrets(code_file)
                sec_json, bp_json, data_flow, cfg_image_location, owap_top_10_highlights = self._analyze_code(content, self.openai_model)
                self.databaseManager.add_information(file_name=code_file, dataflow_json=dumps(data_flow),\
                    owasp_top10_json=dumps(owap_top_10_highlights),\
                    ai_bp_recommendations_json=bp_json, ai_security_recommendations_json=sec_json,\
                    cfg_image_relative_location=cfg_image_location, secrets_found_json=dumps(secrets_found), magik_hash=magik_hash)
                self.logger.info(f"Code file {code_file} analyzed and added to database")
    
    def _analyze_requirements(self, requirements_file_list):
        for req_file in requirements_file_list:
            with open(req_file) as f:
                content = f.read()
                f.close()
            depenencies = self.depenAnalyzer.analyze(content=content)
            self.logger.info(f"Dependencies at {req_file} last analyzed: {depenencies}")
        return self.depenAnalyzer.dependencies        
    
    def _analyze_code(self, content, model):
        try:
            owap_top_10_highlights = self.astAnalyzer.analyze(code=content)
            data_flow = self.flowAnalyzer.analyze(code=content)
            cfg_image_location = self.cfgAnalyzer.generate_cfg(code=content)
            sec_json, bp_json = self._ask_openai(content, model, owap_top_10_highlights)
            return sec_json, bp_json, data_flow, cfg_image_location, owap_top_10_highlights
        except Exception as e:
            self.logger.error(f"Error analyzing code: {e}")
            return None, None, None, None
            
    def _ask_openai(self, content, model, owasp_recos):
        sec_json, total_tokens = self.openaiClient.generate_response(
            task_type="security",
            model=model,
            temperature=0,
            frequency_penalty=0,
            presence_penalty=0,
            code_context=content,
            assistant_context=owasp_recos
        )
        bp_json, total_tokens = self.openaiClient.generate_response(
            task_type="best_practices",
            model=model,
            temperature=0,
            frequency_penalty=0,
            presence_penalty=0,
            code_context=content
        )
        return sec_json, bp_json
            
    def cleanup(self):
        self.fileManager.remove_directory(f"{self.repo_locations}/{self.magik_hash}/*")
        self.logger.info(f"Removed {self.repo_locations}/{self.magik_hash}/*")
        self.fileManager.remove_directory(f"{self.image_store_location}/*")
        self.logger.info(f"Removed all images from {self.image_store_location}/*")
        self.fileManager.remove_file(f"{db_location}")
        self.logger.info(f"Removed database {db_location}")

if __name__ == "__main__":
    from test_secrets import apikey, orgid
    logging.basicConfig(level=logging.DEBUG)
    db_location = "/elfowl/data/database/test.sqlite"
    repo_locations = "/elfowl/data/downloads"
    image_store_location = "/elfowl/data/images"
    openai_model = "gpt-3.5-turbo-1106"
    test_dash = runDashboard(db_location, repo_locations, image_store_location, openai_model=openai_model,\
        api_key=apikey, org_id=orgid, vuln_code_host="nginx", truffles_config_file="/elfowl/truffles_config.yml")
    try:
        test_dash.setup_tables()
        test_repo = "https://github.com/videvelopers/Vulnerable-Flask-App"
        test_branch = "main"
        test_dash.new_repo_sequence(test_repo, test_branch)
        if input("Cleanup? (y/n): ") == "y":
            test_dash.cleanup()
    except Exception as e:
        print(f"Error: {e}")
        test_dash.cleanup()
        exit()