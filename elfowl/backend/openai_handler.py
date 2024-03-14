from openai import OpenAI
import tiktoken
import logging

class OpenAIClient:
    """
    A client for interacting with OpenAI's API to generate responses for various tasks,
    including security analysis and best practices suggestions for code.
    """
    def __init__(self, api_key, org_id):
        """
        Initializes the OpenAI client with API key and organization information.

        :param api_key: The API key for OpenAI.
        :param org_id: The organization ID for OpenAI.
        """
        self.logger = logging.getLogger('OpenAIClient')
        self.client = OpenAI(api_key=api_key, organization=org_id)
        self.logger.debug("OpenAI client initialized")

    def generate_response(self, task_type, model, temperature, frequency_penalty, presence_penalty, code_context, assistant_context=""):
        """
        Generates a response from OpenAI based on the task type.

        :param task_type: The type of task (e.g., 'security', 'best_practices').
        :param model: The OpenAI model to be used for generating the response.
        :param temperature: The temperature setting for the AI model.
        :param frequency_penalty: The frequency penalty setting for the AI model.
        :param presence_penalty: The presence penalty setting for the AI model.
        :param code_context: The code context or content for the analysis.
        :param assistant_context: Additional context for the assistant, if any.
        :return: A tuple containing the response message and the total number of tokens used.
        """
        self.logger.debug(f"Generating {task_type} response from OpenAI")
        if task_type == "security":
            context = [code_context, assistant_context]
            messages = self._construct_security_prompt(context)
        elif task_type == "best_practices":
            context = code_context
            messages = self._construct_best_practices_prompt(context)

        # Calculate max tokens but ensure it does not exceed the model's limit
        calculated_max_tokens = self._count_tokens(model, messages)
        max_tokens = min(calculated_max_tokens, 4096)  # Adjust this limit based on the model's capabilities

        response = self.client.chat.completions.create(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            response_format={"type": "json_object"},
            messages=messages
        )
        self.logger.debug(f"{task_type} response generated")
        return response.choices[0].message.content, response.usage.total_tokens

    def _construct_security_prompt(self, context_list):
        """
        Constructs a security prompt for OpenAI based on the provided context.

        :param context_list: A list containing code context and assistant context.
        :return: A list of messages formatted for the OpenAI API.
        """
        security_prompt = f"""
        3 security experts are discussing code with a panel discussion, trying to analyze it line by line, and make sure the result is correct and avoid penalty:
        Discussion topics are
        Scrutinize each line and larger code constructs for security flaws. Predict flaws that can be exploited by attackers. Indicate the start and end line numbers for the identified issue. This format accommodates both single-line issues and those spanning multiple lines.
        When a vulnerability is found, include its CWE. Contextualize how the issue might affect larger segments of the code.
        Example Response in JSON format:
        {{
            "issues": [{{
                "issueTitle": "Descriptive title of the issue",
                "issue": "The code directly concatenates user input into the `subprocess.check_output` command, making it vulnerable to command injection attacks.",
                "fix": "Use `subprocess.run` with the `shell` parameter set to `True` to prevent command injection.",
                "lineRange": "45 - 53",
                "CWE": "CWE-78",
                "impact": "Attackers can execute arbitrary commands on the server, leading to unauthorized access, data manipulation, and potential system compromise."
            }}]
        }}
        #### Code:
        {context_list[0]}
        """
        assistant_prompt = f"""
        Highlighted lines to consider for possible security vulnerabilities with related 2021 OWASP Top 10 in the format of:
        'A03:2021-Injection': [17, 31, 36, 57, 58, 68, 118, 119, 61]
        #### Highlighted lines:
        {context_list[1]}
        """
        messages = [{"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": assistant_prompt},
                    {"role": "user", "content": security_prompt}]
        return messages
    
    def _construct_best_practices_prompt(self, context):
        """
        Constructs a best practices prompt for OpenAI based on the provided code context.

        :param context: The code context for the analysis.
        :return: A list of messages formatted for the OpenAI API.
        """
        habit_prompt = f"""
        3 software engineering experts are discussing code with a panel discussion, trying to analyze it line by line, and make sure the result is correct and avoid penalty:
        Discussion topics are
        Scrutinize each line and larger code constructs for compliance with industry best practices, particularly in areas like error handling, input validation.
        Critically analyze the code for potential bugs or edge cases and suggest how to address them.
        Example Response in JSON format:
        {{
            "recommendations": [{{
                "issueTitle": "Avoid the use of digits in variable names.",
                "issue": "Single-letter variable names like `v` are not descriptive and can lead to confusion. Use meaningful variable names to improve code readability.",
                "lineRange": "53 - 59",
                "recommendation": "change the variable name from `var1` to `user_input_varible`."
            }}]
        }}
        #### Code:
        {context}
        """
        messages = [{"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": habit_prompt}]
        return messages

    def _count_tokens(self, model, messages):
        """
        Counts the number of tokens in a message based on a specific model's encoding.

        :param model: The OpenAI model to be used.
        :param messages: The messages for which to count tokens.
        :return: The total number of tokens.
        """
        self.logger.debug(f"Counting token for {model}")
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            self.logger.warning("Model not found. Using cl100k_base encoding.")
            encoding = tiktoken.get_encoding("cl100k_base")

        tokens_per_message = 3
        tokens_per_name = 1

        num_tokens = 0
        for message in messages:
            num_tokens += tokens_per_message
            for key, value in message.items():
                num_tokens += len(encoding.encode(value))
                if key == "name":
                    num_tokens += tokens_per_name
        num_tokens += 3  # every reply is primed with assistant
        self.logger.debug(f"Total tokens counted: {num_tokens}")
        return num_tokens


if __name__ == "__main__":
    from secrets import api_key, organization
    from code_analyzer import PythonASTAnalyzer

    model = "gpt-3.5-turbo-1106"
    with open("./examples/Vulnerable-Flask-App/vulnerable-flask-app.py") as f:
        content = f.read()
        f.close()
    
    debug_level = logging.ERROR
    openai_client = OpenAIClient(api_key, organization)
    logging.getLogger('OpenAIClient').setLevel(debug_level)

    ast_analyzer = PythonASTAnalyzer(content)
    vulnerabilities_ast = ast_analyzer.analyze()

    response, total_tokens = openai_client.generate_response(
        task_type="security",
        model=model,
        temperature=0,
        frequency_penalty=0,
        presence_penalty=0,
        code_context=content,
        assistant_context=vulnerabilities_ast
    )
    print(response)
    print(total_tokens)

    response, total_tokens = openai_client.generate_response(
        task_type="best_practices",
        model=model,
        temperature=0,
        frequency_penalty=0,
        presence_penalty=0,
        code_context=content
    )
    print(response)
    print(total_tokens)