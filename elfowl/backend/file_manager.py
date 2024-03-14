import subprocess
import logging

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
            find_command = ['find', directory_path, '-type', 'f', '-iname', '*requirements*']
            self.logger.debug(f"Running find command: {find_command}")
            requirements_file_list = subprocess.check_output(find_command, universal_newlines=True).strip().split("\n")
            if requirements_file_list:
                self.logger.info(f"Requirements files found: {requirements_file_list}")
                return requirements_file_list
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
    file_manager = FileManager()
    files = "/elfowl"
    print(file_manager.list_code_files(files))
    print(file_manager.find_requirements_file(files))
