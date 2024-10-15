import json


class ExperimentResult:
    def __init__(self, id, llm_input, llm_output, ground_truth_CVE: str, ground_truth_CWEs: list,
                 ground_truth_severities: dict, gt_CVSS_version: list, url: str, description: str,
                 date: str, github_description: str):
        self.llm_input = llm_input
        self.id = id
        self.url = url
        self.description = description
        self.date = date
        self.github_description = github_description

        self.ground_truth_CVE = ground_truth_CVE
        self.ground_truth_CWEs = ground_truth_CWEs
        self.ground_truth_severities = ground_truth_severities
        self.ground_truth_CVSS_version = gt_CVSS_version

        self.llm_raw_output = llm_output

        self.error_msg = None
        self.llm_output = None

        if llm_output is None:
            self.error_msg = "LLM OUTPUT IS NONE, POTENTIALLY BECAUSE TOKENS EXCEED"
            return

        try:
            self.llm_output = json.loads(llm_output)
            if self.llm_output is not None:
                if (('EXACT_CWE_IDS' not in self.llm_output) or ('TOP_FIVE_CWE_IDS' not in self.llm_output) or
                        ('SEVERITY_LABEL' not in self.llm_output) or ('SEVERITY_SCORE' not in self.llm_output) or
                        ('EXPLANATION' not in self.llm_output)):
                    self.error_msg = "LLM OUTPUT IS MAL-FORMATTED"
                    return

                self.llm_output['EXACT_CWE_IDS'] = list(set(self.llm_output['EXACT_CWE_IDS']))
                self.llm_output['TOP_FIVE_CWE_IDS'] = list(set(self.llm_output['TOP_FIVE_CWE_IDS']))

                self.llm_output['SEVERITY_LABEL'] = str(self.llm_output['SEVERITY_LABEL'])
                self.llm_output['SEVERITY_SCORE'] = int(self.llm_output['SEVERITY_SCORE'])

                if (str(self.llm_output['SEVERITY_LABEL']).strip().lower() == 'null' or
                        str(self.llm_output['SEVERITY_LABEL']).strip().lower() == 'none'):
                    self.llm_output['SEVERITY_LABEL'] = None

                if self.llm_output['SEVERITY_LABEL'] is not None:
                    self.llm_output['SEVERITY_LABEL'] = self.llm_output['SEVERITY_LABEL'].strip().upper()

                if str(self.llm_output['EXPLANATION']).strip().lower() == 'null':
                    self.llm_output['EXPLANATION'] = None

                if self.llm_output['SEVERITY_SCORE'] < 0:
                    self.llm_output['SEVERITY_SCORE'] = -1

        except Exception as e:
            self.error_msg = str(e)

    def __str__(self):
        return (f"EvaluationResult(id={self.id}, "
                f"llm_input={self.llm_input}, "
                f"url={self.url}, "
                f"description={self.description}, "
                f"date={self.date}, "
                f"github_description={self.github_description}, "
                f"llm_raw_output={self.llm_raw_output}, "
                f"llm_output={json.dumps(self.llm_output)}, "
                f"ground_truth_CVE={self.ground_truth_CVE}, "
                f"ground_truth_CWEs={self.ground_truth_CWEs}, "
                f"ground_truth_severities={self.ground_truth_severities}, "
                f"ground_truth_CVSS_version={self.ground_truth_CVSS_version}, "
                f"error_msg={self.error_msg})")

    def __repr__(self):
        return (f"EvaluationResult(id={self.id}, "
                f"llm_input={self.llm_input!r}, "
                f"url={self.url!r}, "
                f"description={self.description!r}, "
                f"date={self.date!r}, "
                f"github_description={self.github_description!r}, "
                f"llm_raw_output={self.llm_raw_output!r}, "
                f"llm_output={json.dumps(self.llm_output)!r}, "
                f"ground_truth_CVE={self.ground_truth_CVE!r}, "
                f"ground_truth_CWEs={self.ground_truth_CWEs!r}, "
                f"ground_truth_severities={self.ground_truth_severities!r}, "
                f"ground_truth_CVSS_version={self.ground_truth_CVSS_version!r}, "
                f"error_msg={self.error_msg!r}")

    def to_dict(self):
        return {
            'id': self.id,
            'llm_input': self.llm_input,
            'url': self.url,
            'description': self.description,
            'date': self.date,
            'github_description': self.github_description,
            'llm_raw_output': self.llm_raw_output,
            'llm_output': self.llm_output,
            'ground_truth_CVE': self.ground_truth_CVE,
            'ground_truth_CWEs': self.ground_truth_CWEs,
            'ground_truth_severities': self.ground_truth_severities,
            'ground_truth_CVSS_version': self.ground_truth_CVSS_version,
            'error_msg': self.error_msg
        }


class Experimentor:
    def experiment(self, id, llm_input, inference_response: str | None, ground_truth_CVE: str, ground_truth_CWEs: list,
                   ground_truth_severities: dict, gt_CVSS_version: list,
                   url: str, description: str, date: str, github_description: str):
        return ExperimentResult(id, llm_input, inference_response, ground_truth_CVE, ground_truth_CWEs,
                                ground_truth_severities, gt_CVSS_version, url, description, date,
                                github_description).to_dict()
