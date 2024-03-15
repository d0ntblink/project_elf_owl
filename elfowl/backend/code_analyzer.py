import ast
import logging
import requests
import hashlib
from packaging.requirements import Requirement
from py2cfg import CFGBuilder

class PythonASTAnalyzer:
    """
    Analyzes a given Python code snippet for potential security vulnerabilities.
    It checks for a variety of common security issues categorized by OWASP Top Ten.
    """
    def __init__(self):
        """
        Initializes the analyzer with the given Python code.
        """
        self.logger = logging.getLogger(__name__)

    def analyze(self, code):
        """
        Conducts the analysis by invoking various vulnerability-specific methods.
        It aggregates findings into the 'vulnerabilities' dictionary.

        :param code: Python source code as a string.
        :return: A dictionary of identified vulnerabilities categorized by type.
        """
        self.vulnerabilities = {
            "A01:2021-Broken Access Control": [],
            "A02:2021-Cryptographic Failures": [],
            "A03:2021-Injection": [],
            "A05:2021-Security Misconfiguration": [],
            "A07:2021-Identification and Authentication Failures": [],
            "A08:2021-Software and Data Integrity Failures": [],
            "A09:2021-Security Logging and Monitoring Failures": [],
            "A10:2021-Server-Side Request Forgery": []
        }
        self.code = code
        self.analyze_broken_access_control()
        self.analyze_cryptographic_failures()
        self.analyze_injection()
        self.analyze_security_misconfiguration()
        self.analyze_identifcation_and_authentication_failures()
        self.analyze_software_and_data_integrity_failures()
        self.analyze_security_logging_and_monitoring_failures()
        return self.vulnerabilities

    def analyze_injection(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                if func_name == "search_user":
                    if self._is_sql_injection_vulnerable(node):
                        self.vulnerabilities["A03:2021-Injection"].append(node.lineno)
            elif isinstance(node, ast.Call):
                func_name = getattr(node.func, "id", "")
                if self._is_dangerous_function(node):
                    if self._contains_user_input(node):
                        self.vulnerabilities["A03:2021-Injection"].append(node.lineno)
                elif func_name in ["eval", "exec", "os.system"]:
                    self.vulnerabilities["A03:2021-Injection"].append(node.lineno)
                elif isinstance(node.func, ast.Attribute):
                    module_name = getattr(node.func.value, "id", "")
                    if module_name in ["execute", "eval", "subprocess"]:
                        self.vulnerabilities["A03:2021-Injection"].append(node.lineno)
            elif isinstance(node, ast.BinOp):
                if self._is_concatenation_of_user_input(node):
                    self.vulnerabilities["A03:2021-Injection"].append(node.lineno)

    def _is_concatenation_of_user_input(self, node):
        """
        Checks if the expression is concatenation of user input into a SQL query.
        """
        if isinstance(node.op, ast.Add):
            left_operand = self._get_user_input(node.left)
            right_operand = self._get_user_input(node.right)

            if left_operand or right_operand:
                return True
        return False

    def _get_user_input(self, node):
        """
        Checks if the node represents user input.
        """
        if isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Name):
            # Consider variables as potential user input (this may produce false positives)
            return node.id
        elif isinstance(node, ast.Attribute):
            # Consider attributes (e.g., object.property) as potential user input
            return self._get_user_input(node.value) + "." + node.attr
        return None

    def _is_sql_injection_vulnerable(self, node):
        """
        Checks if the SQL construction in the function is vulnerable to injection.
        """
        for child_node in ast.walk(node):
            if isinstance(child_node, ast.BinOp) and isinstance(child_node.op, ast.Mod):
                # Found string formatting operation
                return True
        return False

    def _is_dangerous_function(self, node):
        """
        Checks if the function call involves dangerous operations like generating HTML content.
        """
        dangerous_functions = ["render_template", "HttpResponse", "Response", "write", "writeln"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in dangerous_functions
        return False

    def _contains_user_input(self, node):
        """
        Checks if the function call contains user input without proper sanitization or encoding.
        """
        for arg in node.args:
            if isinstance(arg, ast.Str) and self._looks_like_user_input(arg.s):
                return True
        return False

    def _looks_like_user_input(self, value):
        """
        Check if the value looks like user input.
        """
        # You may need to refine this method based on your application's context and input sources.
        return "user_input" in value.lower()  # Placeholder condition, adjust as needed

    def analyze_software_and_data_integrity_failures(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_deserialization_operation(node):
                    self.vulnerabilities["A08:2021-Software and Data Integrity Failures"].append(node.lineno)

    def _is_deserialization_operation(self, node):
        """
        Checks if the function call involves deserialization operations.
        """
        deserialization_functions = ["json.loads", "json.load", "pickle.loads", "pickle.load"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in deserialization_functions
        return False

    def analyze_identifcation_and_authentication_failures(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = getattr(node.func, "id", "")
                if func_name in ["authenticate", "login", "check_password"]:
                    if self._is_hardcoded_credentials(node):
                        self.vulnerabilities["A07:2021-Identification and Authentication Failures"].append(node.lineno)
            elif isinstance(node, ast.If):
                if self._is_insecure_password_validation(node):
                    self.vulnerabilities["A07:2021-Identification and Authentication Failures"].append(node.lineno)

    def _is_hardcoded_credentials(self, node):
        """
        Checks if there are any hardcoded credentials passed as arguments to the function call.
        """
        for arg in node.args:
            if isinstance(arg, ast.Str) and self._looks_like_credential(arg.s):
                return True
        return False

    def _looks_like_credential(self, value):
        """
        Check if the value looks like a credential (e.g., password).
        """
        common_credentials = ["password", "pass", "pwd", "secret", "token"]
        return any(credential in value.lower() for credential in common_credentials)

    def _is_insecure_password_validation(self, node):
        """
        Checks if the if condition performs insecure password validation.
        """
        if (
            isinstance(node.test, ast.BoolOp) and
            isinstance(node.test.op, ast.And) and
            len(node.test.values) == 2 and
            all(isinstance(value, ast.Compare) for value in node.test.values)
        ):
            for comparison in node.test.values:
                comparator = comparison.comparators[0]
                comparitor_var = None
                
                # Check if comparator is an identifier (variable name)
                if isinstance(comparator, ast.Name):
                    comparitor_var = comparator.id
                # Check if comparator is a constant (string, number, etc.)
                elif isinstance(comparator, ast.Constant):
                    comparitor_var = str(comparator.value)
                    
                if comparitor_var and comparitor_var.lower() in ["password", "pass", "pwd", "token", "secret", "passwd", "user", "username", "uname", "email", "email_address", "e_mail", "e_mail_address", "user_id", "userid", "uid", "user_name", "key", "api_key"]:
                    return True
        return False

    def analyze_cryptographic_failures(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_logging_sensitive_data(node):
                    self.vulnerabilities["A02:2021-Cryptographic Failures"].append(node.lineno)
                elif self._is_sending_sensitive_data(node):
                    self.vulnerabilities["A02:2021-Cryptographic Failures"].append(node.lineno)

    def _is_logging_sensitive_data(self, node):
        """
        Checks if the function call is logging sensitive data.
        """
        logging_functions = ["logging.debug", "logging.info", "logging.warning", "logging.error", "logging.critical"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in logging_functions and self._contains_sensitive_data(node.args)
        return False

    def _is_sending_sensitive_data(self, node):
        """
        Checks if the function call is sending sensitive data over network.
        """
        sending_functions = ["requests.post", "requests.get", "urllib.request.urlopen", "socket.send"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in sending_functions and self._contains_sensitive_data(node.args)
        return False

    def _contains_sensitive_data(self, args):
        """
        Checks if any of the function arguments contain sensitive data.
        """
        for arg in args:
            if isinstance(arg, ast.Str) and self._looks_like_sensitive_data(arg.s):
                return True
        return False

    def _looks_like_sensitive_data(self, value):
        """
        Check if the value looks like sensitive data (e.g., password, API key).
        """
        sensitive_keywords = ["password", "api_key", "secret", "token"]
        return any(keyword in value.lower() for keyword in sensitive_keywords)

    def analyze_broken_access_control(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_authorization_check(node):
                    if self._is_insufficient_access_control(node):
                        self.vulnerabilities["A01:2021-Broken Access Control"].append(node.lineno)
                elif self._is_path_manipulation(node):
                    self.vulnerabilities["A01:2021-Broken Access Control"].append(node.lineno)

    def _is_path_manipulation(self, node):
        """
        Checks if the function call involves path manipulation.
        """
        path_manipulation_functions = [
            "os.path.join", "os.path.expanduser", "os.path.abspath",
            "os.path.dirname", "os.path.basename", "os.path.exists",
            "os.path.isfile", "os.path.isdir", "os.path.realpath",
            "os.path.relpath", "os.path.commonprefix", "os.path.samefile",
            "shutil.move", "shutil.copy", "shutil.copyfile",
            "shutil.copytree", "shutil.rmtree"
        ]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in path_manipulation_functions
        return False

    def _is_authorization_check(self, node):
        """
        Checks if the function call is an authorization check.
        """
        authorization_functions = ["check_permission", "is_authorized", "has_access"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in authorization_functions
        return False

    def _is_insufficient_access_control(self, node):
        """
        Checks if the authorization check is insufficiently enforced.
        """
        for arg in node.args:
            if isinstance(arg, ast.Str) and self._looks_like_permission(arg.s):
                return True
        return False

    def _looks_like_permission(self, value):
        """
        Check if the value looks like a permission or resource identifier.
        """
        common_permissions = ["admin", "user", "role", "privileged"]
        return any(permission in value.lower() for permission in common_permissions)

    def analyze_security_misconfiguration(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if self._is_security_configuration(node):
                    if self._is_misconfigured(node):
                        self.vulnerabilities["A05:2021-Security Misconfiguration"].append(node.lineno)
            elif isinstance(node, ast.Call):
                if self._is_xml_parsing(node):
                    if self._contains_xxe_vulnerability(node):
                        self.vulnerabilities["A05:2021-Security Misconfiguration"].append(node.lineno)

    def _is_xml_parsing(self, node):
        """
        Checks if the function call involves XML parsing.
        """
        xml_parsing_functions = ["xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
                                 "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
                                 "xml.sax.parse", "xml.sax.parseString"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in xml_parsing_functions
        return False

    def _contains_xxe_vulnerability(self, node):
        """
        Checks if the XML parsing operation is vulnerable to XXE.
        """
        for arg in node.args:
            if isinstance(arg, ast.Str) and self._looks_like_xml(arg.s):
                return self._has_external_entity(arg.s)
        return False

    def _looks_like_xml(self, value):
        """
        Check if the value looks like XML data.
        """
        return value.strip().startswith("<") and value.strip().endswith(">")

    def _has_external_entity(self, xml_data):
        """
        Checks if the XML data contains an external entity declaration.
        """
        return "<!DOCTYPE" in xml_data

    def _is_security_configuration(self, node):
        """
        Checks if the assignment involves security-related configuration.
        """
        security_configurations = ["DEBUG", "SECRET_KEY", "ALLOWED_HOSTS", "SECURE_SSL_REDIRECT", "SECURE_HSTS_SECONDS"]
        if isinstance(node.targets[0], ast.Name) and node.targets[0].id in security_configurations:
            return True
        return False

    def _is_misconfigured(self, node):
        """
        Checks if the security configuration is misconfigured.
        """
        value = node.value
        if isinstance(value, ast.Constant):
            if isinstance(value.value, bool):
                # For boolean configurations like DEBUG, SECURE_SSL_REDIRECT, etc.
                return not value.value
            elif isinstance(value.value, str):
                # For string configurations like SECRET_KEY, ALLOWED_HOSTS, etc.
                return value.value == ""
        return False

    def analyze_security_logging_and_monitoring_failures(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_logging_function(node):
                    if self._is_insufficient_logging(node):
                        self.vulnerabilities["A09:2021-Security Logging and Monitoring Failures"].append(node.lineno)

    def _is_logging_function(self, node):
        """
        Checks if the function call is a logging operation.
        """
        logging_functions = ["logging.debug", "logging.info", "logging.warning", "logging.error", "logging.critical"]
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            return func_name in logging_functions
        return False

    def _is_insufficient_logging(self, node):
        """
        Checks if the logging operation is insufficiently detailed.
        """
        if len(node.args) == 0:
            # If no message is provided, it's considered insufficient logging
            return True
        return False

    def analyze_ssrf(self):
        tree = ast.parse(self.code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = getattr(node.func, "id", "")
                if func_name in ["requests.get", "urllib.request.urlopen"]:
                    if self._is_ssrf_vulnerable(node):
                        self.vulnerabilities["A10:2021-Server-Side Request Forgery"].append(node.lineno)

    def _is_ssrf_vulnerable(self, node):
        """
        Checks if the SSRF vulnerability is present in the function call.
        """
        if isinstance(node.args[0], ast.Str):
            url = node.args[0].s
            if (
                url.startswith("http://") or url.startswith("https://") or
                url.startswith("ftp://") or url.startswith("sftp://")
            ):
                return True
        return False


class PythonDataFlow:
    """
    Analyzes the data flow of variables in a Python code snippet.
    It tracks the creation, modification, and usage of variables, especially focusing on user inputs.
    """
    def __init__(self):
        """
        Initializes the data flow analyzer with Python code.
        """
        self.logger = logging.getLogger(__name__)

    def analyze(self, code):
        """
        Conducts the data flow analysis by tracking variables and their usage.

        :param code: Python source code as a string.
        :return: A dictionary of variables with their attributes like type, user input influence, etc.
        """
        self.logger.info("Starting data flow analysis...")
        self.variables_in_flow = {}
        self.code = code
        self.find_variables()
        self.logger.info("Data flow analysis completed.")
        return self.variables_in_flow

    def find_variables(self):
        self.logger.info("Starting variable discovery...")
        tree = ast.parse(self.code)
        current_function = None  # Track the current function name

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                current_function = node.name

            if isinstance(node, ast.Assign):
                self.logger.debug("Found assignment statement.")
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        user_input = self._check_user_input(node.value, current_function)
                        self._variable_entry(target.id, "variable", node.lineno, current_function, user_input)
            elif isinstance(node, ast.For):
                self.logger.debug("Found for loop.")
                if isinstance(node.target, ast.Name):
                    self._variable_entry(node.target.id, "loop_var", node.lineno, current_function, False)
            elif isinstance(node, ast.arg):
                self.logger.debug("Found function argument.")
                self._variable_entry(node.arg, "function_arg", node.lineno, current_function, False)
        self.logger.info("Variable discovery completed.")

    def _variable_entry(self, name, type, lineno, function, user_input):
        if name not in self.variables_in_flow:
            self.logger.debug(f"New variable discovered: {name}.")
            self.variables_in_flow[name] = {
                "type": type,
                "changed_via_input": user_input,
                "first_assigned_at_line": lineno,
                "time_line": [(lineno, function, "assigned")]
            }
        else:
            self._repeating_variable(name, type, lineno, function, user_input)

    def _repeating_variable(self, name, type, lineno, function, user_input):
        self.logger.debug(f"Variable {name} has been modified.")
        # Update timeline
        self.variables_in_flow[name]["time_line"].append((lineno, function, "modified"))
        # Update user input flag if necessary
        if user_input:
            self.variables_in_flow[name]["changed_via_input"] = True

    def _check_user_input(self, value_node, current_function):
        """
        Check if the value_node represents a user input from common sources.
        """
        if isinstance(value_node, ast.Call):
            if hasattr(value_node.func, 'id') and value_node.func.id in ['input', 'get']:
                return True

            if hasattr(value_node.func, 'attr'):
                if value_node.func.attr in ['args', 'form', 'files', 'json']:
                    if isinstance(value_node.func.value, ast.Attribute) and value_node.func.value.attr == 'request':
                        return True

            # Flask route with variable URL (e.g., @app/route('/user/<string:name>'))
            if isinstance(value_node, ast.Attribute) and hasattr(value_node.value, 'id'):
                if value_node.value.id == 'request':
                    if value_node.attr in ['view_args', 'path', 'full_path', 'script_root', 'url', 'base_url']:
                        return True
            
            # Django web framework: form data, file uploads
            if hasattr(value_node.func, 'attr'):
                if value_node.func.attr in ['POST', 'GET', 'FILES']:
                    if hasattr(value_node.func.value, 'id') and value_node.func.value.id == 'request':
                        return True

            # Command-line argument parsing libraries (argparse, click, etc.)
            if hasattr(value_node.func, 'id') and value_node.func.id in ['parse_args', 'get']:
                return True

            # GUI frameworks (e.g., Tkinter, PyQt, etc.)
            if hasattr(value_node.func, 'attr') and value_node.func.attr in ['get', 'getString']:
                # Add specific checks for different GUI libraries as needed
                return True

            # FastAPI and other modern web frameworks
            if hasattr(value_node.func, 'attr'):
                if value_node.func.attr in ['query', 'body', 'form']:
                    # This is a simplistic check; you might want to refine it for specific frameworks
                    return True

            # Checking for file upload patterns in web frameworks
            if hasattr(value_node.func, 'attr') and value_node.func.attr == 'save':
                if hasattr(value_node.func.value, 'attr') and value_node.func.value.attr == 'files':
                    return True

        # Additional checks for attribute access, such as request.method in Flask
        elif isinstance(value_node, ast.Attribute):
            if hasattr(value_node.value, 'id') and value_node.value.id == 'request':
                if value_node.attr in ['args', 'form', 'files', 'json']:
                    return True
            elif value_node.attr in ['args', 'form', 'files', 'json']:
                if isinstance(value_node.value, ast.Name) and value_node.value.id == 'request':
                    return True
        else:
            return False


class CodeCFGAnalyzer:
    """
    Generates a Control Flow Graph (CFG) for a given Python code snippet.
    """
    def __init__(self, save_image_location):
        """
        Initializes the CFG analyzer with Python code.
        """
        self.logger = logging.getLogger(__name__)
        self.save_image_location = save_image_location

    def generate_cfg(self, code):
        """
        Generates a CFG from the code and saves it as a PNG image.

        :param code: Python source code as a string.
        :return: The filename of the generated CFG image.
        """
        self.code = code
        cfg = CFGBuilder().build_from_src('code_analysis', self.code)
        filename = f'cfg_{self._generate_hash()}'  # PNG image filename is hash of the code
        cfg.build_visual(filename, directory=self.save_image_location, format='png', show=False, cleanup=True, build_keys=False, build_own=False)
        self.logger.info(f"CFG image saved as {filename}")
        return f'{self.save_image_location}{filename}.png'

    def _generate_hash(self):
        """
        Generates a SHA256 hash of the code to create a unique filename for the CFG.

        :return: A SHA256 hash string.
        """
        return hashlib.sha256(self.code.encode('utf-8')).hexdigest()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    with open("./examples/Vulnerable-Flask-App/vulnerable-flask-app.py", "r") as f:
        content = f.read()
        f.close()
    with open("./examples/Vulnerable-Flask-App/requirements.txt", "r") as f:
        requirements = f.readlines()
        f.close()
    ast_analyzer = PythonASTAnalyzer()
    highlights = ast_analyzer.analyze(code=content)
    dep_analyzer = PythonDepandaAnalyzer()
    dep_analyzer.analyze(requirements, "requirements")
    dep_analyzer.analyze(content, "code")
    dependecies = dep_analyzer.dependencies
    data_flow = PythonDataFlow()
    var_flow = data_flow.analyze(code=content)
    cfg_analyzer = CodeCFGAnalyzer()
    cfg_image = cfg_analyzer.generate_cfg(code=content)
    print("AST Analysis Results:")
    print(highlights)
    print("\nDependencies And Transitive Dependencies:")
    print(dependecies)
    print("\nData Flow Analysis:")
    print(var_flow)
    print("\nCFG Image:", cfg_image)