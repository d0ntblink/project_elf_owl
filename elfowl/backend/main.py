from flask import Flask, render_template, request, session, send_from_directory
from db_handler import DatabaseManager
from code_analyzer import PythonASTAnalyzer, PythonDataFlow, CodeCFGAnalyzer, PythonDepandaAnalyzer
from openai_handler import OpenAIClient
from cwe_cve_handler import VulnerableCodeSearch
from secret_finder import SecretFinder
from git_handler import GitHandler
from git_handler import FileManager
from test_secrets import apikey, orgid
from json import dumps, loads
import logging, os, time

app = Flask(__name__)
logger = logging.getLogger(__name__)
app.secret_key = 'your_secret_key'
db_manager = DatabaseManager("/elfowl/data/database/git_handler_test.sqlite")

@app.route("/", methods=["GET", "POST"])
def index():
    repositories = db_manager._get_table(table_name="Repository")
    logger.debug(f"Repositories: {repositories}")
    if request.method == "POST":
        repo_origin = request.form["repo_origin"]
        repo_branch = request.form["repo_branch"]
        # Perform the code sequence
        perform_code_sequence(repo_origin, repo_branch)
        return render_template("index.html", message="Code sequence performed successfully!", repositories=repositories)
    else:
        
        return render_template("index.html", repositories=repositories)
    
@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        # Save settings to session
        session['api_key'] = request.form.get('api_key')
        session['organization'] = request.form.get('organization')
        session['model'] = request.form.get('model', 'gpt-3.5-turbo-1106')  # Default model
        return render_template("index.html", message="Settings saved!")
    else:
        return render_template("settings.html")

@app.route("/result/<magik_hash>", methods=["GET"])
def result(magik_hash):
    db = db_manager.retrieve_tables_by_magik_hash(magik_hash)
    if not db:
        return "No information found for this identifier", 404
    logger.debug(f"Got database")
    
    informationMap = db.get('InformationMap', [])
    if not informationMap:
        return "No detailed information found for this identifier", 404
    logger.debug(f"Got informationMap")
    analysis_entries = {}
    for entry in informationMap:
        row = entry[0]-1
        s = "/"
        file_name = s.join(entry[1].split("/")[5:])
        url = f"/result/{magik_hash}/analysis/{row}"
        analysis_entries[file_name] = url

    dependenciesMap = db.get('DependenciesMap', [])
    if not dependenciesMap:
        return "No dependencies found for this identifier", 404
    logger.debug(f"Got dependenciesMap")
    dependencies = dumps(loads(dependenciesMap[1]), indent=2)
    dependencies_vuln = dumps(loads(dependenciesMap[2]), indent=2)
    
    secretsFound = db.get('SecretsFound', [])
    if not secretsFound:
        return "No secrets found for this identifier", 404
    logger.debug(f"Got secretsFound")
    secrets_found = dumps(loads(secretsFound[1]), indent=2)
    
    return render_template("result.html", analysis_entries=analysis_entries, dependencies=dependencies,\
        dependencies_vuln=dependencies_vuln, secretsFound=secrets_found, magik_hash=magik_hash)
    
        

@app.route("/result/<magik_hash>/analysis/<row>", methods=["GET"])
def analysis_result(magik_hash, row):
    info = db_manager.retrieve_tables_by_magik_hash(magik_hash)
    if not info:
        return "No information found for this identifier", 404
    
    # Assuming 'info' is a dict with keys corresponding to table names
    informationMap = info.get('InformationMap', [])
    rowint = int(row)
    if not informationMap:
        return "No detailed information found for this identifier", 404
    
    # Assuming each entry in 'informationMap' corresponds to a row from your table structure
    entry = informationMap[rowint]
    file_location = entry[1]
    try:
        with open(file_location, 'r') as file:
            lines = file.readlines()
            # Determine the number of digits in the last line number to adjust spacing
            max_line_number_length = len(str(len(lines)))
            file_content = ""
            for i, line in enumerate(lines, start=1):
                # Generate line number with consistent spacing
                line_number = f"{i}".rjust(max_line_number_length)
                # Concatenate the line number and line content
                file_content += f"{line_number}: {line}"
    except Exception as e:
        logger.error(f"Error opening file: {str(e)}")
    
    recommendations = loads(entry[4])["recommendations"]
    security_issues = loads(entry[5])["issues"]
    combined_issues = []

    # Adding recommendations to the combined list
    for rec in recommendations:
        start_line = ''.join(c for c in rec.get("lines").replace(" ","").split("-")[0] if c.isdigit())
        combined_issues.append({
            "Type": "Recommendation",  # Assuming you want to include the type for consistency
            "sort_line": start_line,
            "issueTitle": rec.get("issueTitle"),
            "issue": rec.get("issue"),  # Assuming you want to include the issue description for consistency
            "lines": rec.get("line"),
            "recommendation": rec.get("recommendation")
        })

    # Adding security issues to the combined list
    for issue in security_issues:
        # Assuming we want to use the start line of the range for sorting
        start_line = ''.join(c for c in issue.get("lines").replace(" ","").split("-")[0] if c.isdigit())
        logger.debug(f"Start line: {start_line}")
        cwe_num = issue.get("CWE").split("-")[1]
        combined_issues.append({
            "Type": "SecurityIssue",  # Assuming you want to include the type for consistency
            "sort_line": start_line,
            "issueTitle": issue.get("issueTitle"),
            "issue": issue.get("issue"),  # Assuming you want to include the issue description for consistency
            "lines": issue.get("lines"),  # Assuming you want to include the line range for consistency
            "CWE": issue.get("CWE"),
            "cwe_link": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",  # Assuming you want to include a link to the CWE definition
            "suggestedFix": issue.get("fix"),
            "impact": issue.get("impact")
        })

    # Sort combined list by starting line number
    combined_issues_sorted = sorted(combined_issues, key=lambda x: int(x["sort_line"]))

    # Convert the sorted list back to JSON if necessary
    sorted_issues_json = dumps(combined_issues_sorted, indent=2)
    
    flow_picture_url = entry[6]
    
    # Parse the timeline JSON into a list of events
    timeline_json = loads(entry[2])
    timeline = []
    for variable, details in timeline_json.items():
        for event in details['time_line']:
            timeline.append({'line': event[0], 'node_name': variable, 'action': event[2]})
    
    # Sort the timeline by line number
    timeline = sorted(timeline, key=lambda x: x['line'])
    
    # Since the loop will overwrite the variables, ensure to adjust logic if multiple entries are expected

    return render_template("analysis_result.html", file_content=file_content, ai_response_json=sorted_issues_json,\
        flow_picture_url=flow_picture_url, timeline=timeline, magik_hash=magik_hash, row=row)


def perform_code_sequence(repo_origin, repo_branch):
        git_handler = GitHandler("/elfowl/data/downloads")
        file_manager = FileManager()
        ast_analyzer = PythonASTAnalyzer()
        depen_analyzer = PythonDepandaAnalyzer()
        flow_analyzer = PythonDataFlow()
        cfg_analyzer = CodeCFGAnalyzer()
        depen_vuln_search = VulnerableCodeSearch(ip="nginx", lib_type="pypi")
        model = "gpt-3.5-turbo-1106"
        openai_client = OpenAIClient(api_key=apikey, organization=orgid)
        db_manager.create_tables()
        branches = git_handler.get_remote_branches(repo_origin)
        print(branches)
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
            requirements_file = requirements_file.split("\n")
            if type(requirements_file) == str:
                requirements_file = [requirements_file]
            for req_file in requirements_file:
                with open(req_file) as f:
                    content = f.read()
                    f.close()
                depen_analyzer.analyze(content=content)
            if code_file_list:
                for code_file in code_file_list:
                    with open(code_file) as f:
                        content = f.read()
                        f.close()
                    ## if content is smaller than 1000 characters, skip the analysis
                    if len(content) < 2000:
                        continue
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
        print(f"rm -rf ./data/downloads/* && rm -rf ./data/database/git_handler_test.sqlite && rm -rf ./data/images/*")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True, host='0.0.0.0', port=8888)