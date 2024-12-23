MAX_INFERENCE_ITERATION_LOOP = 5
OPENAI_API_KEY = 'TOKEN GOES HERE'
OPENAI_LLM_MAX_TRIAL = 3
PROJECT_ABSOLUTE_PATH = "FOLDER PATH GOES HERE"
LLM_TEMPERATURE = 1
LLM_TOP_P = 1
LLM_PRESENCE_PENALTY = 0
LLM_FREQUENCY_PENALTY = 0
LLM_TRIAL_GAP_SECONDS = 3
MAX_TOKEN_NUMBER = 16385
LLM_NORMAL_MODEL = 'gpt-3.5-turbo'
LLM_CWE_FINE_TUNED_MODEL = 'FINE-TUNED MODEL ID GOES HERE'
LLM_SEVERITY_FINE_TUNED_MODEL = 'FINE-TUNED MODEL ID GOES HERE'
CODE_TAGS = ['<Code>', '</Code>']
HUNK_TAGS = ['<Hunk>', '</Hunk>']
METHOD_TAGS = ['<Method>', '</Method>']
LLM_MODEL_CUT_OFF_DATE = '2021-09-01'
LLM_RESPONSE_ERROR_SIGNS = ["Traceback (most recent call last)", "Bad gateway"]

# prompt 1
LLM_SYSTEM_FIELD_FOR_BUGGY_FILE_SEVERITY = """You are an expert in assessing the severity of vulnerabilities in software code.

Instructions:
1. * Input: You will receive one or more files, each has a file name, and file content enclosed  within <Code> and </Code>. If there are multiple buggy codes, they will be related to the same bug. The provided input structure is as below:
   File: file_name
   Content: <Code> content </Code>

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the buggy code(s) has a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the buggy code(s) has a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If a severity assessment is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity assessment identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

# prompt 2
LLM_SYSTEM_FIELD_FOR_BUGGY_FILE_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) in software code.

Instructions:
1. * Input: You will receive one or more files, each has a file name, and file content enclosed  within <Code> and </Code>. If there are multiple buggy codes, they will be related to the same bug. The provided input structure is as below:
   File: file_name
   Content: <Code> content </Code>

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: List any identify CWE IDs from the buggy code(s) provided (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five most relevant CWE IDs if applicable (e.g., ["CWE-123", "CWE-456"]). If no CWEs are found, leave this as an empty array [].

Example Outputs:
1. If CWEs are identified:
   {
     "EXACT_CWE_IDS": ["CWE-79", "CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-79", "CWE-89", "CWE-20", "CWE-22", "CWE-352"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""

# prompt 1
LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD_SEVERITY = """You are an expert in assessing the severity of vulnerabilities in software code.

Instructions:
1. * Input: You will receive one or more files, each has a file name, and one or more buggy methods enclosed  within <Method> and </Method>. If there are multiple buggy methods or files, they will be related to the same bug. The provided input structure is as below:
   File: file_name
   Methods: 
        <Method> method 1 </Method>
        <Method> method 2 </Method>

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the buggy code(s) has a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the buggy code(s) has a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If a severity assessment is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity assessment identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

# prompt 2
LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) in software code.

Instructions:
1. * Input: You will receive one or more files, each has a file name, and one or more buggy methods enclosed  within <Method> and </Method>. If there are multiple buggy methods or files, they will be related to the same bug. The provided input structure is as below:
   File: file_name
   Methods: 
        <Method> method 1 </Method>
        <Method> method 2 </Method>

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: List any identify CWE IDs from the buggy code(s) provided (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five most relevant CWE IDs if applicable (e.g., ["CWE-123", "CWE-456"]). If no CWEs are found, leave this as an empty array [].

Example Outputs:
1. If CWEs are identified:
   {
     "EXACT_CWE_IDS": ["CWE-79", "CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-79", "CWE-89", "CWE-20", "CWE-22", "CWE-352"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""

# prompt 1
LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS_SEVERITY = """You are an expert in assessing the severity of vulnerabilities in software code.

Instructions:
1. * Input: You will receive one or more files, each has a file name, and one or more buggy hunks enclosed  within <Hunk> and </Hunk>. If there are multiple buggy hunks or files, they will be related to the same bug. The provided input structure is as below:
   File: file_name
   Hunks:
        <Hunk> hunk 1 </Hunk>
        <Hunk> hunk 2 </Hunk>

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the buggy code(s) has a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the buggy code(s) has a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If a severity assessment is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity assessment identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

# prompt 2
LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) in software code.

Instructions:
1. * Input: You will receive one or more files, each has a file name, and one or more buggy hunks enclosed  within <Hunk> and </Hunk>. If there are multiple buggy hunks or files, they will be related to the same bug. The provided input structure is as below:
   File: file_name
   Hunks:
        <Hunk> hunk 1 </Hunk>
        <Hunk> hunk 2 </Hunk>

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: List any identify CWE IDs from the buggy code(s) provided (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five most relevant CWE IDs if applicable (e.g., ["CWE-123", "CWE-456"]). If no CWEs are found, leave this as an empty array [].

Example Outputs:
1. If CWEs are identified:
   {
     "EXACT_CWE_IDS": ["CWE-79", "CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-79", "CWE-89", "CWE-20", "CWE-22", "CWE-352"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""

# prompt 1
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_SEVERITY = """You are an expert in assessing the severity of vulnerabilities based on the description of software bugs.

Instructions:
1. * Input:
    Description: You will receive a description of a bug.

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the description indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the description indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If a severity assessment is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity assessment identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

# prompt 2
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) based on the description of software bugs.

Instructions:
1. * Input:
    Description: You will receive a description of a bug.

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: List any identify CWE IDs in the provided description of the bug (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five most relevant CWE IDs in the provided description of the bug if applicable (e.g., ["CWE-123", "CWE-456"]). If no CWEs are found, leave this as an empty array [].

Example Outputs:
1. If CWEs are identified:
   {
     "EXACT_CWE_IDS": ["CWE-79", "CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-79", "CWE-89", "CWE-20", "CWE-22", "CWE-352"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""

# prompt 1
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES_SEVERITY = """You are an expert in assessing the severity of vulnerabilities based on both the buggy code(s) and bug description.

Instructions:
1. * Input: You will receive one or more sections of buggy files enclosed within <Code> and </Code>, and a description of the buggy code. If there are multiple buggy files, they will be related to the same bug. You may receive multiple file names and their contents provided as:
   Description: description of the bug
   File: file_name
   Content:
        <Code> content </Code>

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the provided information indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the provided information indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If severity is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity is identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

#  prompt 2
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) based on both the buggy code(s) and bug description.

Instructions:
1. * Input: You will receive one or more sections of buggy files enclosed within <Code> and </Code>, and a description of the buggy code. If there are multiple buggy files, they will be related to the same bug. You may receive multiple file names and their contents provided as:
   Description: description of the bug
   File: file_name
   Content:
        <Code> content </Code>

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: If you identify any CWE IDs in the provided buggy code(s) or its description, list them here (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five CWE IDs in the provided buggy code(s) or its description (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].

Example Outputs:
1. If CWEs are found:
   {
     "EXACT_CWE_IDS": ["CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-89", "CWE-79", "CWE-20", "CWE-352", "CWE-285"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""


# prompt 1
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS_SEVERITY = """You are an expert in assessing the severity of vulnerabilities based on both the buggy method(s) and bug description.

Instructions:
1. * Input: You will receive one or more file names, each having one or more buggy methods enclosed within <Method> and </Method>, and a description of the buggy code. If there are multiple buggy methods or files, they will be related to the same bug. The provided input structure is provided as:
   Description: description of the bug
   File: file_name
   Methods:
        <Method> method 1 </Method>
        <Method> method 2 </Method>

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the provided information indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the provided information indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If severity is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity is identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

# prompt 2
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) based on both the buggy method(s) and bug description.

Instructions:
1. * Input: You will receive one or more file names, each having one or more buggy methods enclosed within <Method> and </Method>, and a description of the buggy code. If there are multiple buggy methods or files, they will be related to the same bug. The provided input structure is provided as:
   Description: description of the bug
   File: file_name
   Methods:
        <Method> method 1 </Method>
        <Method> method 2 </Method>

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: If you identify any CWE IDs in the provided buggy method(s) or its description, list them here (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five CWE IDs in the provided buggy method(s) or its description (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].

1. If CWEs are found:
   {
     "EXACT_CWE_IDS": ["CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-89", "CWE-79", "CWE-20", "CWE-352", "CWE-285"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""

# prompt 1
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS_SEVERITY = """You are an expert in assessing the severity of vulnerabilities based on both the buggy hunk(s) and bug description.

Instructions:
1. * Input: You will receive one or more file names, each having one or more buggy hunks enclosed within <Hunk> and </Hunk>, and a description of the buggy code. If there are multiple buggy hunks or files, they will be related to the same bug. The provided input structure is provided as:
   Description: description of the bug
   File: file_name
   Hunks:
        <Hunk> hunk 1 </Hunk>
        <Hunk> hunk 2 </Hunk>

2. * Output: Generate a JSON object with the following structure:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Output Details:
- SEVERITY_LABEL: If the provided information indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity level (e.g., "high") based on CVSS %s . If there are no vulnerabilities, set this field to null.
- SEVERITY_SCORE: If the provided information indicates a security vulnerability (CVE) considering predicted CWE_IDs, provide its severity score as a float number based on CVSS %s . If there are no vulnerabilities, set this field to -1.

Example Outputs:
1. If severity is identified:
   {
     "SEVERITY_LABEL": "high",
     "SEVERITY_SCORE": 8.3
   }

2. If no severity is identified:
   {
     "SEVERITY_LABEL": null,
     "SEVERITY_SCORE": -1
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.

%s
"""

# prompt 2
LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS_CWE = """You are an expert in identifying Common Weakness Enumerations (CWEs) based on both the buggy hunk(s) and bug description.

Instructions:
1. * Input: You will receive one or more file names, each having one or more buggy hunks enclosed within <Hunk> and </Hunk>, and a description of the buggy code. If there are multiple buggy hunks or files, they will be related to the same bug. The provided input structure is provided as:
   Description: description of the bug
   File: file_name
   Hunks:
        <Hunk> hunk 1 </Hunk>
        <Hunk> hunk 2 </Hunk>

2. * Output: Generate a JSON object with the following structure:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Output Details:
- EXACT_CWE_IDS: If you identify any CWE IDs in the provided buggy hunk(s) or its description, list them here (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].
- TOP_FIVE_CWE_IDS: List of top five CWE IDs in the provided buggy hunk(s) or its description (e.g., ["CWE-123"]). If no CWEs are found, leave this as an empty array [].

1. If CWEs are found:
   {
     "EXACT_CWE_IDS": ["CWE-89"],
     "TOP_FIVE_CWE_IDS": ["CWE-89", "CWE-79", "CWE-20", "CWE-352", "CWE-285"]
   }

2. If no CWEs are identified:
   {
     "EXACT_CWE_IDS": [],
     "TOP_FIVE_CWE_IDS": []
   }

Important: Your output must strictly follow the described JSON structure. Do not include any additional fields, descriptions, or text.
"""

DEFAULT_SEVERITY_VERSION_FOR_CVSS = 'V3.1'

CVSS_SEVERITY_DESCRIPTIONS = {'V2.0': """CVSS v2.0 Guide:

Base Metrics:
1.	Access Vector (AV): How the vulnerability is exploited (Network (N), Adjacent Network (A), Local (L))
2.	Access Complexity (AC): Complexity of the attack (Low (L), Medium (M), High (H))
3.	Authentication (Au): Number of times an attacker must authenticate (None (N), Single (S), Multiple (M))
4.	Confidentiality (C), Integrity (I), Availability (A): Impact on security properties (None (N), Partial (P), Complete (C))

Severity Levels and Example Combinations:
1. Low (0.0 – 3.9): These vulnerabilities are somewhat difficult to exploit or have limited impact. For example, “AV:L/AC:M/Au:S/C:N/I:N/A:N” and “AV:A/AC:M/Au:S/C:P/I:P/A:N”
3. Medium (4.0 - 6.9): Involves vulnerabilities that are exploitable and could cause moderate damage. For example, “AV:N/AC:L/Au:S/C:N/I:P/A:N” and “AV:N/AC:L/Au:N/C:C/I:N/A:P”
4. High (7.0 – 10.0): Represents vulnerabilities that are easier to exploit and have significant consequences. For example, “AV:N/AC:M/Au:S/C:P/I:N/A:C” and “AV:N/AC:L/Au:N/C:C/I:C/A:C”

Note: The severity level may change based on specific characteristics of the vulnerability. For example, if the access vector is local but the impact on availability is complete, the severity might increase.
""",
                              'V3.0':
                                  """"CVSS v3.0 Guide:

Base Metrics:
1.	Attack Vector (AV): How the vulnerability is exploited (Network (N), Adjacent Network (A), Local (L), Physical (P))
2.	Attack Complexity (AC): Difficulty of exploitation (Low (L), High (H))
3.	Privileges Required (PR): Level of required privileges an attacker needs to exploit the vulnerability (None (N), Low (L), High (H))
4.	User Interaction (UI): Need for user interaction (None (N), Required (R))
5.	Scope (S): Impact on other components (Unchanged (U), Changed (C))
6.	Confidentiality (C), Integrity (I), Availability (A): Impact on security properties (None (N), Low (L), High (H))

Severity Levels and Example Combinations:
1. None (0.0): This vulnerability is extremely difficult to exploit and has minimal impact. For example, “AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N” and “AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N”
2. Low (0.1 - 3.9): These vulnerabilities are somewhat difficult to exploit or have limited impact. For example, “AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:L” and “AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N”
3. Medium (4.0 - 6.9): Involves vulnerabilities that are exploitable and could cause moderate damage. For example, “AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N” and “AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L”
4. High (7.0 - 8.9): Represents vulnerabilities that are easier to exploit and have significant consequences. For example, “AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L” and “AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L”
5. Critical (9.0 - 10.0): These vulnerabilities are both easy to exploit and have a devastating impact. For example, “AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H” and “AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H”

Note: The severity level may change based on specific characteristics of the vulnerability. For example, if the attack vector is physical but the impact on availability is high, the severity might increase.

                                  """,
                              'V3.1': """CVSS v3.1 Guide:

Base Metrics:
1.	Attack Vector (AV): How the vulnerability is exploited (Network (N), Adjacent Network (A), Local (L), Physical (P))
2.	Attack Complexity (AC): Difficulty of exploitation (Low (L), High (H))
3.	Privileges Required (PR): Level of required privileges an attacker needs to exploit the vulnerability (None (N), Low (L), High (H))
4.	User Interaction (UI): Need for user interaction (None (N), Required (R))
5.	Scope (S): Impact on other components (Unchanged (U), Changed (C))
6.	Confidentiality (C), Integrity (I), Availability (A): Impact on security properties (None (N), Low (L), High (H))

Severity Levels and Example Combinations:
1. None (0.0): This vulnerability is extremely difficult to exploit and has minimal impact. For example, “AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N” and “AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N”
2. Low (0.1 - 3.9): These vulnerabilities are somewhat difficult to exploit or have limited impact. For example, “AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:L” and “AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N”
3. Medium (4.0 - 6.9): Involves vulnerabilities that are exploitable and could cause moderate damage. For example, “AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N” and “AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L”
4. High (7.0 - 8.9): Represents vulnerabilities that are easier to exploit and have significant consequences. For example, “AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L” and “AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L”
5. Critical (9.0 - 10.0): These vulnerabilities are both easy to exploit and have a devastating impact. For example, “AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H” and “AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H”

Note: The severity level may change based on specific characteristics of the vulnerability. For example, if the attack vector is physical but the impact on availability is high, the severity might increase.
"""}

DATA_PATH = './data/cve_training.json'
EVALUATION_DATASET_PATH = './data/evaluation_dataset.json'
FINE_TUNING_JSON_DATASET_PATH = './data/fine_tuning_dataset.json'
FINE_TUNING_JSONL_DATASET_TRAIN_PATH_SEVERITY = './data/fine_tuning_severity_train_dataset.jsonl'
FINE_TUNING_JSONL_DATASET_TEST_PATH_SEVERITY = './data/fine_tuning_severity_test_dataset.jsonl'
FINE_TUNING_JSONL_DATASET_TRAIN_PATH_CWE = './data/fine_tuning_cwe_train_dataset.jsonl'
FINE_TUNING_JSONL_DATASET_TEST_PATH_CWE = './data/fine_tuning_cwe_test_dataset.jsonl'
DATASET_SPLIT_RATIO = 0.5
FINE_TUNING_TRAIN_SPLIT_RATIO = 0.75
TOP_CWE_PATH = './data/top_cwe.json'
CVE2CWE_PATH = './data/cve_to_cwe_2016_2024.json'

ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS = ['php', 'js', 'py', 'go', 'c', 'cpp', 'ts', 'rb', 'java']
TEMP_CONTENT_FILE_NAME_FOR_METHOD_EXTRACTOR = 'temp'
PYTHON_EXTRACTOR_SCRIPT_PATH = 'extractors/python_method_extractor.py'
JS_EXTRACTOR_SCRIPT_PATH = 'extractors/js_parser.py'
JAVA_EXTRACTOR_SCRIPT_PATH = 'extractors/java_parser.py'
PHP_EXTRACTOR_SCRIPT_PATH = 'extractors/php_parser.py'
TS_EXTRACTOR_SCRIPT_PATH = 'extractors/ts_parser.py'
C_EXTRACTOR_SCRIPT_PATH = 'extractors/c_parser.py'
CPP_EXTRACTOR_SCRIPT_PATH = 'extractors/cpp_parser.py'
GO_EXTRACTOR_SCRIPT_PATH = 'extractors/go_parser.py'
RB_EXTRACTOR_SCRIPT_PATH = 'extractors/ruby_parser.py'

ANALYSIS_RADIUS = [0.5, 1, 1.5]
SEVERITY_SCORE_RANGES = {
    'V2.0': {
        "LOW": (0.0, 3.9),
        "MEDIUM": (4.0, 6.9),
        "HIGH": (7.0, 10)
    },
    'V3.0': {
        "LOW": (0.1, 3.9),
        "MEDIUM": (4.0, 6.9),
        "HIGH": (7.0, 8.9),
        "CRITICAL": (9.0, 10.0)
    },
    'V3.1': {
        "LOW": (0.1, 3.9),
        "MEDIUM": (4.0, 6.9),
        "HIGH": (7.0, 8.9),
        "CRITICAL": (9.0, 10.0)
    }
}

MAX_NUMBER_OF_RECORDS_PER_EXPERIMENT = -1
MAX_NUMBER_OF_FILTERED_RECORDS_PER_EXPERIMENT = 500
EXPERIMENT_STAGE = False

ANALYZE_STAGE = not EXPERIMENT_STAGE
