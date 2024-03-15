import sqlite3
import hashlib
import logging
from datetime import datetime

class DatabaseManager:
    """
    A class to manage interactions with a SQLite database, providing functionalities
    to create tables, add and sync repository data, add information, and retrieve specific fields.
    """
    def __init__(self, db_file):
        """
        Initializes the DatabaseManager with a specific SQLite database file.

        :param db_file: Path to the SQLite database file.
        """
        self.logger = logging.getLogger(__name__)
        self.db_file = db_file

    def create_tables(self):
        """
        Creates the necessary tables in the database if they do not already exist.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Create Repository Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Repository (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT NOT NULL,
                    repo_origin TEXT NOT NULL,
                    repo_branch TEXT NOT NULL,
                    repo_location TEXT UNIQUE NOT NULL,
                    added_by TEXT NOT NULL,
                    added_on TEXT NOT NULL,
                    last_synced_by TEXT,
                    last_synced_on TEXT,
                    last_commit_msg TEXT,
                    last_commit_short_hash TEXT,
                    magik_hash TEXT NOT NULL UNIQUE
                )
            ''')
            # Create Information Map Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS InformationMap (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    dataflow_json TEXT,
                    owasp_top10_json TEXT,
                    ai_bp_recommendations_json TEXT,
                    ai_security_recommendations_json TEXT,
                    cfg_image_relative_location TEXT,
                    secrets_found_json TEXT,
                    magik_hash TEXT NOT NULL
                )
            ''')
            # Create Dependencies Map Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS DependenciesMap (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dependencies_json TEXT,
                    dependencies_cve_vuln_found_json TEXT,
                    magik_hash TEXT NOT NULL UNIQUE
                )
            ''')
            conn.commit()
            self.logger.info("Tables created successfully.")
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Error creating tables: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def add_repository(self, repo_name, repo_origin, repo_branch, repo_location, added_by, last_commit_msg, last_commit_short_hash):
        """
        Adds a new repository record to the Repository table.

        :param repo_name: Name of the repository.
        :param repo_origin: Origin URL of the repository.
        :param repo_branch: Branch of the repository.
        :param repo_location: Location of the repository on the local file system.
        :param added_by: User who added the repository.
        :param last_commit_msg: Last commit message in the repository.
        :param last_commit_short_hash: Short hash of the last commit.
        """
        try:
            magik_hash = self._generate_magik_hash(repo_name, repo_branch, last_commit_short_hash)
            date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO Repository (repo_name, repo_origin, repo_branch, repo_location, added_by, added_on, last_synced_by, last_synced_on, last_commit_msg, last_commit_short_hash, magik_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (repo_name, repo_origin, repo_branch, repo_location, added_by, date_time, added_by, date_time, last_commit_msg, last_commit_short_hash, magik_hash))
            conn.commit()
            self.logger.info("Repository added successfully.")
            return magik_hash, True
        except sqlite3.Error as e:
            self.logger.error(f"Error adding repository: {e}")
            return None, False
        finally:
            if conn:
                conn.close()

    def sync_repository(self, repo_name, repo_branch, last_synced_by, last_commit_msg, last_commit_short_hash):
        """
        Updates the synchronization details of a specific repository in the Repository table.

        :param repo_name: Name of the repository.
        :param repo_branch: Branch of the repository.
        :param last_synced_by: User who performed the last synchronization.
        :param last_commit_msg: Last commit message during the synchronization.
        :param last_commit_short_hash: Short hash of the last commit during synchronization.
        """
        try:
            magik_hash = self._generate_magik_hash(repo_name, repo_branch, last_commit_short_hash)
            date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._set_fields(table_name="Repository", set_clauses=["last_synced_by", "last_synced_on", "last_commit_msg", "last_commit_short_hash", "magik_hash"]\
                , set_values=[last_synced_by, date_time, last_commit_msg, last_commit_short_hash, magik_hash]\
                , where_clauses=["repo_name", "repo_branch"], where_values=[repo_name, repo_branch])
            self.logger.info("Repository synced successfully.")
            return magik_hash, True
        except Exception as e:
            self.logger.error(f"Error syncing repository: {e}")
            return None, False

    def add_information(self, file_name, dataflow_json, owasp_top10_json, ai_bp_recommendations_json,
                        ai_security_recommendations_json, cfg_image_relative_location, secrets_found_json, magik_hash):
        """
        Adds a new information record to the InformationMap table.

        :param file_name: Name of the file associated with the information.
        :param dataflow_json: JSON string of data flow information.
        :param owasp_top10_json: JSON string of OWASP Top 10 information.
        :param ai_bp_recommendations_json: JSON string of AI best practices recommendations.
        :param ai_security_recommendations_json: JSON string of AI security recommendations.
        :param cfg_image_relative_location: Relative location of the CFG image.
        :param secrets_found_json: JSON string of found secrets.
        :param magik_hash: Magik hash associated with the information.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO InformationMap (file_name, dataflow_json, owasp_top10_json,
                                           ai_bp_recommendations_json, ai_security_recommendations_json,
                                           cfg_image_relative_location, secrets_found_json, magik_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (file_name, dataflow_json, owasp_top10_json, ai_bp_recommendations_json,
                  ai_security_recommendations_json, cfg_image_relative_location, secrets_found_json, magik_hash))
            conn.commit()
            self.logger.info("Information added successfully.")
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Error adding information: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def add_dependencies(self, dependencies_json, dependencies_cve_vuln_found_json, magik_hash):
        """
        Adds a new information record to the InformationMap table.

        :param dependencies_json: JSON string of dependencies information.
        :param dependencies_cve_vuln_found_json: JSON string of found dependencies CVE vulnerabilities.
        :param magik_hash: Magik hash associated with the information.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO DependenciesMap (dependencies_json , dependencies_cve_vuln_found_json, magik_hash)
                VALUES (?, ?, ?)
            ''', (dependencies_json, dependencies_cve_vuln_found_json, magik_hash))
            conn.commit()
            self.logger.info("Information added successfully.")
        except sqlite3.Error as e:
            self.logger.error(f"Error adding information: {e}")
        finally:
            if conn:
                conn.close()
    
    def add_secrets_found(self, secrets_found_json, magik_hash):
        """
        Adds a new information record to the InformationMap table.

        :param secrets_found_json: JSON string of secrets found.
        :param magik_hash: Magik hash associated with the information.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO SecretsFound (secrets_found_json, magik_hash)
                VALUES (?, ?)
            ''', (secrets_found_json, magik_hash))
            conn.commit()
            self.logger.info("Information added successfully.")
        except sqlite3.Error as e:
            self.logger.error(f"Error adding information: {e}")
        finally:
            if conn:
                conn.close()

    def update_repository_field(self, magik_hash, field_name, field_value):
        """
        Updates a specific field of a repository in the Repository table.

        :param repo_name: Name of the repository.
        :param repo_branch: Branch of the repository.
        :param field_name: Name of the field to be updated.
        :param field_value: New value for the field.
        """
        self._set_fields(table_name="Repository", set_clauses=[field_name], set_values=[field_value], where_clauses=["magik_hash"], where_values=[magik_hash])
        self.logger.info(f"Field {field_name} updated successfully.")

    def _generate_magik_hash(self, repo_name, repo_branch, last_commit_short_hash):
        """
        Generates a unique MD5 hash based on the provided arguments.

        :param args: Arguments used to generate the hash.
        :return: MD5 hash string.
        """
        magik_string = ''.join(map(str, [repo_name, repo_branch, last_commit_short_hash]))
        return hashlib.md5(magik_string.encode()).hexdigest()

    def get_filenames_by_magik_hash(self, magik_hash):
        """
        Retrieves filenames from the InformationMap table based on a given magik hash.

        :param magik_hash: The magik hash to filter by.
        :return: List of filenames associated with the given magik hash.
        """
        filenames = self._retrieve_fields(table_name="InformationMap", field_name="file_name", where_clauses=["magik_hash"], where_values=[magik_hash], one_or_all="all")
        self.logger.debug(f"File names for magik hash {magik_hash}: {filenames}")
        if filenames:
            return [filename[0] for filename in filenames]
        else:
            self.logger.warning(f"No file names found for magik hash {magik_hash}")
            return []

    def retrieve_tables_by_magik_hash(self, magik_hash):
        """
        Retrieves rows of information from every table that matches the given magik_hash.

        :param magik_hash: The magik hash to filter by.
        :return: A dictionary containing information from all relevant tables.
        """
        info = {}
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Retrieve Repository info
            cursor.execute('SELECT * FROM Repository WHERE magik_hash = ?', (magik_hash,))
            repo_info = cursor.fetchone()
            if repo_info:
                info['Repository'] = repo_info

            # Retrieve InformationMap info
            cursor.execute('SELECT * FROM InformationMap WHERE magik_hash = ?', (magik_hash,))
            info_map = cursor.fetchall()
            if info_map:
                info['InformationMap'] = info_map

            # Retrieve DependenciesMap info
            cursor.execute('SELECT * FROM DependenciesMap WHERE magik_hash = ?', (magik_hash,))
            dependencies_info = cursor.fetchone()
            if dependencies_info:
                info['DependenciesMap'] = dependencies_info

            return info
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving information by magik_hash {magik_hash}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def retrieve_field_by_magik_hash_and_filename(self, magik_hash, filename, field_name):
        """
        Retrieves a specific field from the InformationMap table based on a magik hash and filename.

        :param magik_hash: The magik hash to filter by.
        :param filename: The filename to filter by.
        :param field_name: The field to retrieve.
        :return: The value of the field, or None if not found.
        """
        result = self._retrieve_fields(table_name="InformationMap", field_name=field_name, where_clauses=["magik_hash"], where_values=[magik_hash], one_or_all="one")
        if result:
            return result
        else:
            return None

    def retrieve_field_by_repo_name_and_branch(self, repo_name, repo_branch, field_name):
        """
        Retrieves a specific field from the Repository table based on the repository name and branch.

        :param repo_name: The name of the repository.
        :param repo_branch: The branch of the repository.
        :param field_name: The field to retrieve.
        :return: The value of the field, or None if not found.
        """
        magik_hash = self._get_magik_hash(repo_name, repo_branch)
        result = self._retrieve_fields(table_name="Repository", field_name=field_name, where_clauses=["magik_hash"], where_values=[magik_hash], one_or_all="one")
        if result:
            return result
        else:
            return None
    
    def _retrieve_fields(self, table_name, field_name, where_clauses, where_values, one_or_all="one"):
        """
        Retrieves a specific field from a given table based on provided WHERE clauses.

        :param table_name: The name of the table to query.
        :param field_name: The field to retrieve.
        :param where_clauses: A list of WHERE clauses for filtering.
        :param where_values: A list of values corresponding to the WHERE clauses.
        :param one_or_all: Specifies whether to fetch one record or all records that match.
        :return: The value of the field, a list of values, or None if not found.
        """
        if (type(where_clauses) == "<class 'list'>" and type(where_values) == "<class 'list'>") and (len(where_clauses) != len(where_values)):
            self.logger.error(f"The number of where clauses {len(where_clauses)} and values {len(where_values)} must be equal.")
            return None
        try:
            self.logger.debug(f"Retrieving {field_name} with the WHERE clauses: {where_clauses}")
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Construct the WHERE clause
            where_clause_combined = " AND ".join([f"{clause} = ?" for clause in where_clauses])
            query = f'''
                SELECT {field_name}
                FROM {table_name}
                WHERE {where_clause_combined}
            '''
            self.logger.debug(f"Executing query: {query}, {where_values}")
            cursor.execute(query, tuple(where_values))
            if one_or_all == "all":
                result = cursor.fetchall()
            else:
                result = cursor.fetchone()
            
            if result:
                return result[0] if one_or_all == "one" else result
            else:
                return None
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving {field_name} with the WHERE clauses: {e}")
            return None
        finally:
            if conn:
                conn.close()
                
    def _set_fields(self, table_name, set_clauses, set_values, where_clauses=["1"], where_values=["1"]):
        """
        Sets specific fields in a given table based on provided WHERE clauses.

        :param table_name: The name of the table to query.
        :param set_clauses: A list of SET clauses for updating fields.
        :param set_values: A list of values corresponding to the SET clauses.
        :param where_clauses: A list of WHERE clauses for filtering.
        :param where_values: A list of values corresponding to the WHERE clauses.
        """
        if (type(set_clauses) == "<class 'list'>" and type(set_values) == "<class 'list'>") and (len(set_clauses) != len(set_values)):
            self.logger.error(f"The number of set clauses {len(set_clauses)} and values {len(set_values)} must be equal.")
            return
        if (type(where_clauses) == "<class 'list'>" and type(where_values) == "<class 'list'>") and (len(where_clauses) != len(where_values)):
            self.logger.error(f"The number of where clauses {len(where_clauses)} and values {len(where_values)} must be equal.")
            return
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Construct the SET clause
            set_clause_combined = ", ".join([f"{clause} = ?" for clause in set_clauses])
            # Construct the WHERE clause
            where_clause_combined = " AND ".join([f"{clause} = ?" for clause in where_clauses])
            query = f'''
                UPDATE {table_name}
                SET {set_clause_combined}
                WHERE {where_clause_combined}
            '''
            query_values = tuple(set_values) + tuple(where_values)
            self.logger.debug(f"Executing query: {query}, {query_values}")
            cursor.execute(query, query_values)
            conn.commit()
            self.logger.info("Fields updated successfully.")
        except sqlite3.Error as e:
            self.logger.error(f"Error updating fields: {e}")
        finally:
            if conn:
                conn.close()

    def _get_magik_hash(self, repo_name, repo_branch):
        """
        Retrieves the magik hash based on the repository name and branch.

        :param repo_name: Name of the repository.
        :param repo_branch: Branch of the repository.
        :return: The magik hash, or None if not found.
        """
        result = self._retrieve_fields(table_name="Repository", field_name="magik_hash", where_clauses=["repo_name", "repo_branch"]\
            , where_values=[repo_name, repo_branch], one_or_all="one")
        if result:
            return result
        else:
            return None
        
    def _get_table(self, table_name):
        """
        Retrieves the entire table.

        :param table_name: Name of the table.
        :return: The table, or None if not found.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            result = cursor.fetchall()
            if result:
                return result
            else:
                return None
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving table: {e}")
            return None
        finally:
            if conn:
                conn.close()


if __name__ == "__main__":
    import random
    import string
    import json
    logging.basicConfig(level=logging.DEBUG)

    # Initialize the DatabaseManager with the database file
    db_manager = DatabaseManager('./data/database/git_handler_test.sqlite')
    tables = db_manager._get_table("Repository")
    print(tables)
    # # Check if the database exists, if not, create it
    # db_manager.create_tables()
    # def random_string(length=5):
    #     letters = string.ascii_lowercase
    #     return ''.join(random.choice(letters) for _ in range(length))
    # # Add repositories
    # hash_list = []
    # repo_and_branch = {}
    # for i in range(3):
    #     repo_name = random_string(5)
    #     repo_origin = f"https://github.com/{repo_name}"
    #     repo_branch = 'dev' + random_string(4)
    #     lcmsg = random_string(20)
    #     lcshh = random_string(7)
    #     added_by = random_string(5)
    #     hash_list.append(db_manager._generate_magik_hash(repo_name, repo_branch, lcshh))
    #     repo_and_branch[repo_name] = repo_branch
    #     repo_location = f"./data/downloads/{hashlib.md5((''.join(map(str, [repo_name, repo_branch]))).encode()).hexdigest()}"
    #     db_manager.add_repository(repo_name, repo_origin, repo_branch, repo_location, added_by, lcmsg, lcshh)

    # # Sync repositories
    # for repo, branch in repo_and_branch.items():
    #     last_synced_by = random_string(5)
    #     last_commit_msg = random_string(20)
    #     last_commit_short_hash = random_string(7)
    #     db_manager.sync_repository(repo, branch, last_synced_by, last_commit_msg, last_commit_short_hash)

    # # Add information
    # for i in range(40):
    #     dataflow_json = json.dumps({"data": random_string(5)})
    #     dependencies_json = json.dumps({"dependencies": random_string(5)})
    #     owasp_top10_json = json.dumps({"owasp": random_string(5)})
    #     ai_bp_recommendations_json = json.dumps({"ai_bp": random_string(5)})
    #     ai_security_recommendations_json = json.dumps({"ai_security": random_string(5)})
    #     cfg_image_relative_location = random_string(5)
    #     dependencies_cve_vuln_found_json = json.dumps({"cve_vuln": random_string(5)})
    #     file_name = random_string(5)
    #     magik_hash = random.choice(hash_list)
    #     db_manager.add_information(dataflow_json, dependencies_json, owasp_top10_json, ai_bp_recommendations_json,
    #                                ai_security_recommendations_json, cfg_image_relative_location,
    #                                dependencies_cve_vuln_found_json, file_name, magik_hash)
    
    # # Retrieve filenames by magik hash
    # magik_hash = random.choice(hash_list)
    # print(db_manager.get_filenames_by_magik_hash(magik_hash))
    
    # # Retrieve field by magik hash and filename
    # magik_hash = random.choice(hash_list)
    # filename = random_string(5)
    # print(db_manager.retrieve_field_by_magik_hash_and_filename(magik_hash, filename, "dataflow_json"))
    
    # # Retrieve field by repo name and branch
    # repo_name = random.choice(list(repo_and_branch.keys()))
    # print
    # repo_branch = repo_and_branch[repo_name]
    # print(db_manager.retrieve_field_by_repo_name_and_branch(repo_name, repo_branch, "last_commit_msg"))
    