import subprocess
import json
import logging

class SecretFinder:
    """
    Secret finder class.
    """

    def __init__(self, config_file='', repo_location=''):
        """
        Initialize the secret finder.

        Args:
            config_file (str): Path to the Trufflehog configuration file.
            repo_location (str): Path to the repository to search for secrets.
        """
        self.config_file = config_file
        self.repo_location = repo_location
        self.refined_secrets = {}
        
    def find_secrets(self):
        """
        Find secrets in the repository with truffleHog.

        Returns:
            list: List of secrets found in the repository.
        """
        if self.config_file == '':
            command = f"trufflehog filesystem {self.repo_location} --json"
        else:
            command = f"trufflehog filesystem {self.repo_location} --config={self.config_file} --json"
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            findings = result.stdout.split('\n')
            refined = self.extract_fields(findings)
            return refined
        
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running Trufflehog: {e}")
            return []
        
    def extract_fields(self, json_data_list):
        """
        Extracts the verified, raw, redacted, and extra data fields from the JSON data and appends them to a dictionary.

        Args:
            json_data (str): JSON data string.

        Returns:
            dict: Dictionary containing the extracted fields.
        """
        n = 0
        for json_data in json_data_list:
            if json_data == '':
                continue
            logging.debug(f"Extracting fields from: {json_data}")
            logging.debug(f"length of json_data_list: {len(json_data_list)} we are at {n}")
            data = json.loads(json_data)
            name = f"Possible Secret #{n} - {data.get('DetectorName', None)}"
            extracted_fields = {
                "Metadata": data.get("SourceMetadata", None),
                "Verified": data.get("Verified", None),
                "Raw": data.get("Raw", None)
                # "Redacted": data.get("Redacted", None),
                # "ExtraData": data.get("ExtraData", None)
            }
            self.refined_secrets[name] = extracted_fields
            n += 1
        return self.refined_secrets

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    secret_finder = SecretFinder(config_file='truffles_config.yml', repo_location='.')
    secrets = secret_finder.find_secrets()
    print(secrets)