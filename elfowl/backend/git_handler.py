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
            return target_directory
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error cloning repository: {e}")
            return "cloning failed"

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


if __name__ == "__main__":
    pass