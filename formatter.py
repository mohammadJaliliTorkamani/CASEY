import json


class ExperimentResult:
    def __init__(self, id, severity_llm_pack, cwe_llm_pack, ground_truth_CVE: str, ground_truth_CWEs: list,
                 ground_truth_severities: dict, gt_CVSS_version: list, url: str, description: str,
                 date: str, github_description: str):
        assert severity_llm_pack[0] == 'SEVERITY'
        self.severity_llm_input, self.severity_llm_raw_output = severity_llm_pack[1], severity_llm_pack[2]
        assert cwe_llm_pack[0] == 'CWE'
        self.cwe_llm_input, self.cwe_llm_raw_output = cwe_llm_pack[1], cwe_llm_pack[2]

        self.id = id
        self.url = url
        self.description = description
        self.date = date
        self.github_description = github_description

        self.ground_truth_CVE = ground_truth_CVE
        self.ground_truth_CWEs = ground_truth_CWEs
        self.ground_truth_severities = ground_truth_severities
        self.ground_truth_CVSS_version = gt_CVSS_version

        self.cwe_error_msg = None
        self.severity_error_msg = None

        self.severity_llm_output = None
        self.cwe_llm_output = None

        if self.severity_llm_raw_output is None:
            self.severity_error_msg = "SEVERITY LLM OUTPUT IS NONE, POTENTIALLY BECAUSE TOKENS EXCEED"
        else:
            self.process_severity()

        if self.cwe_llm_raw_output is None:
            self.cwe_error_msg = "CWE LLM OUTPUT IS NONE, POTENTIALLY BECAUSE TOKENS EXCEED"
        else:
            self.process_cwe()

    def process_cwe(self):
        try:
            self.cwe_llm_output = json.loads(self.cwe_llm_raw_output)
            if self.cwe_llm_output is not None:
                if (('EXACT_CWE_IDS' not in self.cwe_llm_output) or ('TOP_FIVE_CWE_IDS' not in self.cwe_llm_output)):
                    self.cwe_error_msg = "CWE LLM OUTPUT IS MAL-FORMATTED"
                else:
                    self.cwe_llm_output['EXACT_CWE_IDS'] = list(set(self.cwe_llm_output['EXACT_CWE_IDS']))
                    self.cwe_llm_output['TOP_FIVE_CWE_IDS'] = list(set(self.cwe_llm_output['TOP_FIVE_CWE_IDS']))

                    if not set(self.cwe_llm_output['EXACT_CWE_IDS']).issubset(
                            set(self.cwe_llm_output['TOP_FIVE_CWE_IDS'])):
                        self.cwe_error_msg = "EXACT_CWE_IDS IS NOT A SUBSET OF TOP_FIVE_CWE_IDS"

        except Exception as e:
            self.cwe_error_msg = str(e)

    def process_severity(self):
        self.severity_llm_output = json.loads(self.severity_llm_raw_output)
        if (
                ('SEVERITY_LABEL' not in self.severity_llm_output) or (
                'SEVERITY_SCORE' not in self.severity_llm_output)):
            self.severity_error_msg = "SEVERITY LLM OUTPUT IS MAL-FORMATTED"
            return
        try:
            self.severity_llm_output = json.loads(self.severity_llm_raw_output)
            if self.severity_llm_output is not None:
                if (('SEVERITY_LABEL' not in self.severity_llm_output) or (
                        'SEVERITY_SCORE' not in self.severity_llm_output)):
                    self.severity_error_msg = "SEVERITY LLM OUTPUT IS MAL-FORMATTED"
                else:
                    self.severity_llm_output['SEVERITY_LABEL'] = str(self.severity_llm_output['SEVERITY_LABEL'])
                    self.severity_llm_output['SEVERITY_SCORE'] = int(self.severity_llm_output['SEVERITY_SCORE'])

                    if (str(self.severity_llm_output['SEVERITY_LABEL']).strip().lower() == 'null' or
                            str(self.severity_llm_output['SEVERITY_LABEL']).strip().lower() == 'none'):
                        self.severity_llm_output['SEVERITY_LABEL'] = None

                    if self.severity_llm_output['SEVERITY_LABEL'] is not None:
                        self.severity_llm_output['SEVERITY_LABEL'] = self.severity_llm_output[
                            'SEVERITY_LABEL'].strip().upper()

                    if self.severity_llm_output['SEVERITY_SCORE'] < 0:
                        self.severity_llm_output['SEVERITY_SCORE'] = -1

                    if self.severity_llm_output['SEVERITY_LABEL'] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"]:
                        self.severity_error_msg = "SEVERITY LABEL IS MAL-FORMATTED"
        except Exception as e:
            self.severity_error_msg = str(e)

    def __str__(self):
        return (f"EvaluationResult(id={self.id}, "
                f"severity_llm_input={self.severity_llm_input}, "
                f"cwe_llm_input={self.cwe_llm_input}, "
                f"url={self.url}, "
                f"description={self.description}, "
                f"date={self.date}, "
                f"github_description={self.github_description}, "
                f"severity_llm_raw_output={self.severity_llm_raw_output}, "
                f"cwe_llm_raw_output={self.cwe_llm_raw_output}, "
                f"severity_llm_output={json.dumps(self.severity_llm_output)}, "
                f"cwe_llm_output={json.dumps(self.cwe_llm_output)}, "
                f"ground_truth_CVE={self.ground_truth_CVE}, "
                f"ground_truth_CWEs={self.ground_truth_CWEs}, "
                f"ground_truth_severities={self.ground_truth_severities}, "
                f"ground_truth_CVSS_version={self.ground_truth_CVSS_version}, "
                f"severity_error_msg={self.severity_error_msg}, "
                f"cwe_error_msg={self.cwe_error_msg})")

    def __repr__(self):
        return (f"EvaluationResult(id={self.id}, "
                f"severity_llm_input={self.severity_llm_input!r}, "
                f"cwe_llm_input={self.cwe_llm_input!r}, "
                f"url={self.url!r}, "
                f"description={self.description!r}, "
                f"date={self.date!r}, "
                f"github_description={self.github_description!r}, "
                f"severity_llm_raw_output={self.severity_llm_raw_output!r}, "
                f"cwe_llm_raw_output={self.cwe_llm_raw_output!r}, "
                f"severity_llm_output={json.dumps(self.severity_llm_output)!r}, "
                f"cwe_llm_output={json.dumps(self.cwe_llm_output)!r}, "
                f"ground_truth_CVE={self.ground_truth_CVE!r}, "
                f"ground_truth_CWEs={self.ground_truth_CWEs!r}, "
                f"ground_truth_severities={self.ground_truth_severities!r}, "
                f"ground_truth_CVSS_version={self.ground_truth_CVSS_version!r}, "
                f"severity_error_msg={self.severity_error_msg!r}, "
                f"cwe_error_msg={self.cwe_error_msg!r}")

    def to_dict(self):
        return {
            'id': self.id,
            'severity_llm_input': self.severity_llm_input,
            'cwe_llm_input': self.cwe_llm_input,
            'url': self.url,
            'description': self.description,
            'date': self.date,
            'github_description': self.github_description,
            'severity_llm_raw_output': self.severity_llm_raw_output,
            'cwe_llm_raw_output': self.cwe_llm_raw_output,
            'severity_llm_output': self.severity_llm_output,
            'cwe_llm_output': self.cwe_llm_output,
            'ground_truth_CVE': self.ground_truth_CVE,
            'ground_truth_CWEs': self.ground_truth_CWEs,
            'ground_truth_severities': self.ground_truth_severities,
            'ground_truth_CVSS_version': self.ground_truth_CVSS_version,
            'severity_error_msg': self.severity_error_msg,
            'cwe_error_msg': self.cwe_error_msg
        }


class Formatter:
    def format(self, id, severity_llm_pack, cwe_llm_pack, ground_truth_CVE: str, ground_truth_CWEs: list,
               ground_truth_severities: dict, gt_CVSS_version: list,
               url: str, description: str, date: str, github_description: str):
        return ExperimentResult(id, severity_llm_pack, cwe_llm_pack, ground_truth_CVE, ground_truth_CWEs,
                                ground_truth_severities, gt_CVSS_version, url, description, date,
                                github_description).to_dict()
