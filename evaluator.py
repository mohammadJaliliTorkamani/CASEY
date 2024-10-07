import datetime
import json
from enum import Enum


class EvaluationResult:
    class CWE_EvaluationResultEnum(Enum):
        IDENTICAL = 0
        GT_SUBSET_OF_PR = 1
        PR_SUBSET_OF_GT = 2
        EMPTY_PR = 3
        EMPTY_GT = 4
        NOT_OVERLAPPED = 5
        OVERLAPPED = 6

        def __str__(self) -> str:
            return f"{self.name}"

    def __init__(self, llm_input, llm_output, ground_truth_CVE: str, ground_truth_CWEs: list,
                 ground_truth_severities: dict,
                 gt_CVSS_version: list, url: str, description: str, date: str, github_description: str):
        self.llm_input = llm_input

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

        try:
            self.llm_output = json.loads(llm_output)
            if self.llm_output is not None:
                self.llm_output['CWE_IDS'] = list(set(self.llm_output['CWE_IDS']))
                if self.llm_output['severity'] == 'null':
                    self.llm_output['severity'] = None
                else:
                    self.llm_output['severity'] = self.llm_output['severity'].upper()

                self.equal_severity = (self.llm_output['severity'] is not None and
                                       len(self.ground_truth_severities) > 0 and
                                       str(self.llm_output['severity']).lower() == str(
                            self.ground_truth_severities[self.ground_truth_CVSS_version[0]]).lower())

                self.cwe_evaluation = self.calculate_cwe_evaluation(self.llm_output['CWE_IDS'], self.ground_truth_CWEs)
                self.is_equal = ((self.equal_severity) and
                                 (self.cwe_evaluation == EvaluationResult.CWE_EvaluationResultEnum.IDENTICAL))
            else:
                self.is_equal = False
        except Exception as e:
            self.is_equal = False
            self.error_msg = str(e)

    def __str__(self):
        return (f"EvaluationResult(llm_input={self.llm_input}, "
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
                f"is_equal={self.is_equal},"
                f"error_msg={self.error_msg},"
                f"equal_severity={self.equal_severity},"
                f"cwe_evaluation={self.cwe_evaluation})")

    def __repr__(self):
        return (f"EvaluationResult(llm_input={self.llm_input!r}, "
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
                f"is_equal={self.is_equal!r}, "
                f"error_msg={self.error_msg!r}, "
                f"equal_severity={self.equal_severity!r}, "
                f"cwe_evaluation={self.cwe_evaluation!r})")

    def to_dict(self):
        return {
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
            'is_equal': self.is_equal,
            'error_msg': self.error_msg,
            'equal_severity': self.equal_severity,
            'cwe_evaluation': str(self.cwe_evaluation)
        }

    def calculate_cwe_evaluation(self, predicted_CWEs: list, ground_truth_CWEs: list) -> CWE_EvaluationResultEnum:
        predicted_CWEs_set = set(predicted_CWEs)
        ground_truth_CWEs_set = set(ground_truth_CWEs)

        if len(predicted_CWEs_set) == 0:
            return EvaluationResult.CWE_EvaluationResultEnum.EMPTY_PR
        elif len(ground_truth_CWEs_set) == 0:
            return EvaluationResult.CWE_EvaluationResultEnum.EMPTY_GT
        elif predicted_CWEs_set == ground_truth_CWEs_set:
            return EvaluationResult.CWE_EvaluationResultEnum.IDENTICAL
        elif ground_truth_CWEs_set.issubset(predicted_CWEs_set):
            return EvaluationResult.CWE_EvaluationResultEnum.GT_SUBSET_OF_PR
        elif predicted_CWEs_set.issubset(ground_truth_CWEs_set):
            return EvaluationResult.CWE_EvaluationResultEnum.PR_SUBSET_OF_GT
        elif ground_truth_CWEs_set.isdisjoint(predicted_CWEs_set):
            return EvaluationResult.CWE_EvaluationResultEnum.NOT_OVERLAPPED
        return EvaluationResult.CWE_EvaluationResultEnum.OVERLAPPED


class Evaluator:
    def evaluate(self, llm_input, inference_response: str | None, ground_truth_CVE: str, ground_truth_CWEs: list,
                 ground_truth_severities: dict, gt_CVSS_version: list,
                 url: str, description: str, date: str, github_description: str):
        return EvaluationResult(llm_input, inference_response, ground_truth_CVE, ground_truth_CWEs,
                                ground_truth_severities, gt_CVSS_version, url, description, date,
                                github_description).to_dict()

    @staticmethod
    def analyze_evaluations(evaluations: list[dict]):
        equal_counter = 0
        cwe_identical_counter = 0
        cwe_gt_subset_of_pr_counter = 0
        cwe_pr_subset_of_gt_counter = 0
        cwe_empty_pr_counter = 0
        cwe_empty_gt_counter = 0
        cwe_non_overlapped_counter = 0
        cwe_overlapped_counter = 0
        equal_severity_counter = 0
        invalid_inference_counter = 0

        for evaluation in evaluations:
            if evaluation['is_equal']:
                equal_counter += 1
            if evaluation['equal_severity'] is True:
                equal_severity_counter += 1
            if evaluation['llm_output'] is None:
                invalid_inference_counter += 1

            if evaluation['cwe_evaluation'] == "IDENTICAL":
                cwe_identical_counter += 1
            elif evaluation['cwe_evaluation'] == "GT_SUBSET_OF_PR":
                cwe_gt_subset_of_pr_counter += 1
            elif evaluation['cwe_evaluation'] == "PR_SUBSET_OF_GT":
                cwe_pr_subset_of_gt_counter += 1
            elif evaluation['cwe_evaluation'] == "EMPTY_PR":
                cwe_empty_pr_counter += 1
            elif evaluation['cwe_evaluation'] == "EMPTY_GT":
                cwe_empty_gt_counter += 1
            elif evaluation['cwe_evaluation'] == "NOT_OVERLAPPED":
                cwe_non_overlapped_counter += 1
            elif evaluation['cwe_evaluation'] == "OVERLAPPED":
                cwe_overlapped_counter += 1

        return {
            'total_number_of_samples': len(evaluations),
            'timestamp': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'equal': equal_counter,
            'accuracy_overall': 0 if len(evaluations) == 0 else (equal_counter / len(evaluations)),
            'accuracy_CWE': 0 if len(evaluations) == 0 else cwe_identical_counter / len(evaluations),
            'accuracy_severity': 0 if len(evaluations) == 0 else equal_severity_counter / len(evaluations),
            'CWE_identical': cwe_identical_counter,
            'CWE_gt_subset_of_pr': cwe_gt_subset_of_pr_counter,
            'CWE_pr_subset_of_gt': cwe_pr_subset_of_gt_counter,
            'CWE_empty_pr': cwe_empty_pr_counter,
            'CWE_empty_gt': cwe_empty_gt_counter,
            'CWE_non_overlapped': cwe_non_overlapped_counter,
            'CWE_overlapped': cwe_overlapped_counter,
            'equal_severities': equal_severity_counter,
            'invalid_inferences': invalid_inference_counter,
            'cwe_evaluations': evaluations}
