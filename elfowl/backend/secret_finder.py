import subprocess
import json
import logging

class SecretFinder:
    """
    Secret finder class.
    """

    def __init__(self, config_file=''):
        """
        Initialize the secret finder.

        Args:
            config_file (str): Path to the Trufflehog configuration file.
            repo_location (str): Path to the repository to search for secrets.
        """
        self.config_file = config_file
        self.logger = logging.getLogger(__name__)
        
    def find_secrets(self, file_path):
        """
        Find secrets in the repository with truffleHog.

        Returns:
            list: List of secrets found in the repository.
        """
        if self.config_file == '':
            command = f"trufflehog filesystem {file_path} --json"
        else:
            command = f"trufflehog filesystem {file_path} --config={self.config_file} --json"
        try:
            self.logger.debug(f"Running Trufflehog with command: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            self.logger.debug(f"Trufflehog result: {result.stdout}")
            findings = result.stdout.split('\n')
            self.logger.debug(f"findings: {findings}")
            refined = self.extract_fields(findings)
            return refined
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running Trufflehog: {e}")
            return []
        
    def extract_fields(self, json_data_list):
        """
        Extracts the verified, raw, redacted, and extra data fields from the JSON data and appends them to a dictionary.

        Args:
            json_data (str): JSON data string.

        Returns:
            dict: Dictionary containing the extracted fields.
        """
        refined_secrets = {}
        n = 0
        for json_data in json_data_list:
            if json_data == '':
                continue
            self.logger.debug(f"Extracting fields from: {json_data}")
            self.logger.debug(f"length of json_data_list: {len(json_data_list)} we are at {n}")
            data = json.loads(json_data)
            name = f"Possible Secret #{n} - {data.get('DetectorName', None)}"
            extracted_fields = {
                "Metadata": data.get("SourceMetadata", None),
                "Verified": data.get("Verified", None),
                "Raw": data.get("Raw", None)
                # "Redacted": data.get("Redacted", None),
                # "ExtraData": data.get("ExtraData", None)
            }
            refined_secrets[name] = extracted_fields
            n += 1
        self.logger.info(f"Found possible secrets: {refined_secrets}")
        return refined_secrets

if __name__ == "__main__":
    pass