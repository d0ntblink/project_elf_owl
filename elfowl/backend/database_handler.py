import sqlite3
import hashlib
import logging
from datetime import datetime

class DatabaseManager:
    """
    A class to manage interactions with a SQLite database, providing functionalities
    to create tables, add and sync repository data, add information, and retrieve specific fields.
    """

    def __init__(self, db_file, repositry_table_name="Repository",
                 information_map_table_name="InformationMap",
                 dependencies_map_table_name="DependenciesMap"):
        """
        Initializes the DatabaseManager with a specific SQLite database file.

        Args:
            db_file (str): Path to the SQLite database file.
        """
        self.logger = logging.getLogger(__name__)
        self.db_file = db_file
        self.repositry_table_name = repositry_table_name
        self.information_map_table_name = information_map_table_name
        self.dependencies_map_table_name = dependencies_map_table_name

    def create_tables(self):
        """
        Creates the necessary tables in the database if they do not already exist.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Create Repository Table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {self.repositry_table_name} (
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
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {self.information_map_table_name} (
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
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {self.dependencies_map_table_name} (
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

        Args:
            repo_name (str): Name of the repository.
            repo_origin (str): Origin URL of the repository.
            repo_branch (str): Branch of the repository.
            repo_location (str): Location of the repository on the local file system.
            added_by (str): User who added the repository.
            last_commit_msg (str): Last commit message in the repository.
            last_commit_short_hash (str): Short hash of the last commit.

        Returns:
            Tuple[str, bool]: A tuple containing the magik hash and a boolean indicating the success of adding the repository.
        """
        try:
            magik_hash = self._generate_magik_hash(repo_name, repo_branch, last_commit_short_hash)
            date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(f'''
                INSERT INTO {self.repositry_table_name} (repo_name, repo_origin, repo_branch, repo_location, added_by, added_on, last_synced_by, last_synced_on, last_commit_msg, last_commit_short_hash, magik_hash)
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

        Args:
            repo_name (str): Name of the repository.
            repo_branch (str): Branch of the repository.
            last_synced_by (str): User who performed the last synchronization.
            last_commit_msg (str): Last commit message during the synchronization.
            last_commit_short_hash (str): Short hash of the last commit during synchronization.

        Returns:
            Tuple[str, bool]: A tuple containing the magik hash and a boolean indicating the success of the synchronization.
        """
        try:
            magik_hash = self._generate_magik_hash(repo_name, repo_branch, last_commit_short_hash)
            date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._set_fields(table_name=self.repositry_table_name, set_clauses=["last_synced_by", "last_synced_on", "last_commit_msg", "last_commit_short_hash", "magik_hash"]\
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

        Args:
            file_name (str): Name of the file associated with the information.
            dataflow_json (str): JSON string of data flow information.
            owasp_top10_json (str): JSON string of OWASP Top 10 information.
            ai_bp_recommendations_json (str): JSON string of AI best practices recommendations.
            ai_security_recommendations_json (str): JSON string of AI security recommendations.
            cfg_image_relative_location (str): Relative location of the CFG image.
            secrets_found_json (str): JSON string of found secrets.
            magik_hash (str): Magik hash associated with the information.

        Returns:
            bool: True if the information is added successfully, False otherwise.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(f'''
                INSERT INTO {self.information_map_table_name} (file_name, dataflow_json, owasp_top10_json,
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

        Args:
            dependencies_json (str): JSON string of dependencies information.
            dependencies_cve_vuln_found_json (str): JSON string of found dependencies CVE vulnerabilities.
            magik_hash (str): Magik hash associated with the information.
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(f'''
                INSERT INTO {self.dependencies_map_table_name} (dependencies_json , dependencies_cve_vuln_found_json, magik_hash)
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

        Args:
            secrets_found_json (str): JSON string of secrets found.
            magik_hash (str): Magik hash associated with the information.
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

        Args:
            magik_hash (str): The magik hash of the repository.
            field_name (str): The name of the field to be updated.
            field_value (str): The new value for the field.
        """
        self._set_fields(table_name=self.repositry_table_name, set_clauses=[field_name], set_values=[field_value], where_clauses=["magik_hash"], where_values=[magik_hash])
        self.logger.info(f"Field {field_name} updated successfully.")

    def _generate_magik_hash(self, repo_name, repo_branch, last_commit_short_hash):
        """
        Generates a unique MD5 hash based on the provided arguments.

        Args:
            repo_name (str): The name of the repository.
            repo_branch (str): The branch of the repository.
            last_commit_short_hash (str): The short hash of the last commit.

        Returns:
            str: The MD5 hash string.
        """
        magik_string = ''.join(map(str, [repo_name, repo_branch, last_commit_short_hash]))
        return hashlib.md5(magik_string.encode()).hexdigest()

    def get_filenames_by_magik_hash(self, magik_hash):
        """
        Retrieves filenames from the InformationMap table based on a given magik hash.

        Args:
            magik_hash (str): The magik hash to filter by.

        Returns:
            List[str]: List of filenames associated with the given magik hash.
        """
        filenames = self._retrieve_fields(table_name=self.information_map_table_name, field_name="file_name", where_clauses=["magik_hash"], where_values=[magik_hash], one_or_all="all")
        self.logger.debug(f"File names for magik hash {magik_hash}: {filenames}")
        if filenames:
            return [filename[0] for filename in filenames]
        else:
            self.logger.warning(f"No file names found for magik hash {magik_hash}")
            return []

    def retrieve_tables_by_magik_hash(self, magik_hash):
        """
        Retrieves rows of information from every table that matches the given magik_hash.

        Args:
            magik_hash (str): The magik hash to filter by.

        Returns:
            Optional[Dict[str, Any]]: A dictionary containing information from all relevant tables.
        """
        info = {}
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Retrieve Repository info
            cursor.execute(f'SELECT * FROM {self.repositry_table_name} WHERE magik_hash = ?', (magik_hash,))
            repo_info = cursor.fetchone()
            if repo_info:
                info[self.repositry_table_name] = repo_info

            # Retrieve InformationMap info
            cursor.execute(f'SELECT * FROM {self.information_map_table_name} WHERE magik_hash = ?', (magik_hash,))
            info_map = cursor.fetchall()
            if info_map:
                info[self.information_map_table_name] = info_map

            # Retrieve DependenciesMap info
            cursor.execute(f'SELECT * FROM {self.dependencies_map_table_name} WHERE magik_hash = ?', (magik_hash,))
            dependencies_info = cursor.fetchone()
            if dependencies_info:
                info[self.dependencies_map_table_name] = dependencies_info

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

        Args:
            magik_hash (str): The magik hash to filter by.
            filename (str): The filename to filter by.
            field_name (str): The field to retrieve.

        Returns:
            The value of the field, or None if not found.
        """
        result = self._retrieve_fields(table_name=self.information_map_table_name, field_name=field_name, where_clauses=["magik_hash"], where_values=[magik_hash], one_or_all="one")
        if result:
            return result
        else:
            return None

    def retrieve_field_by_repo_name_and_branch(self, repo_name, repo_branch, field_name):
        """
        Retrieves a specific field from the Repository table based on the repository name and branch.

        Args:
            repo_name (str): The name of the repository.
            repo_branch (str): The branch of the repository.
            field_name (str): The field to retrieve.

        Returns:
            The value of the field, or None if not found.
        """
        magik_hash = self._get_magik_hash(repo_name, repo_branch)
        result = self._retrieve_fields(table_name=self.repositry_table_name, field_name=field_name, where_clauses=["magik_hash"], where_values=[magik_hash], one_or_all="one")
        if result:
            return result
        else:
            return None
    
    def _retrieve_fields(self, table_name, field_name, where_clauses, where_values, one_or_all="one"):
        """
        Retrieves a specific field from a given table based on provided WHERE clauses.

        Args:
            table_name (str): The name of the table to query.
            field_name (str): The field to retrieve.
            where_clauses (list): A list of WHERE clauses for filtering.
            where_values (list): A list of values corresponding to the WHERE clauses.
            one_or_all (str, optional): Specifies whether to fetch one record or all records that match. Defaults to "one".

        Returns:
            The value of the field, a list of values, or None if not found.
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

        Args:
            table_name (str): The name of the table to query.
            set_clauses (list): A list of SET clauses for updating fields.
            set_values (list): A list of values corresponding to the SET clauses.
            where_clauses (list, optional): A list of WHERE clauses for filtering. Defaults to ["1"].
            where_values (list, optional): A list of values corresponding to the WHERE clauses. Defaults to ["1"].
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

        Args:
            repo_name (str): Name of the repository.
            repo_branch (str): Branch of the repository.

        Returns:
            str: The magik hash, or None if not found.
        """
        result = self._retrieve_fields(table_name=self.repositry_table_name, field_name="magik_hash", where_clauses=["repo_name", "repo_branch"]\
            , where_values=[repo_name, repo_branch], one_or_all="one")
        if result:
            return result
        else:
            return None
        
    def _get_table(self, table_name):
        """
        Retrieves the entire table.

        Args:
            table_name (str): Name of the table.

        Returns:
            List[Tuple]: The table, or None if not found.
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
    pass