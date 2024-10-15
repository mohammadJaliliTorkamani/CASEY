from enum import Enum

import constants


class Evaluator:
    class CWE_EvaluationResultEnum(Enum):
        IDENTICAL_E = 0
        IDENTICAL_T = 1
        IDENTICAL_U = 2
        GT_SUBSET_OF_PR_E = 3
        GT_SUBSET_OF_PR_T = 4
        GT_SUBSET_OF_PR_U = 5
        PR_SUBSET_OF_GT_E = 6
        PR_SUBSET_OF_GT_T = 7
        PR_SUBSET_OF_GT_U = 8
        EMPTY_PR_E = 9
        EMPTY_PR_T = 10
        EMPTY_PR_U = 11
        NOT_OVERLAPPED_E = 12
        NOT_OVERLAPPED_T = 13
        NOT_OVERLAPPED_U = 14
        OVERLAPPED_E = 15
        OVERLAPPED_T = 16
        OVERLAPPED_U = 17

    class SeverityLabel_EvaluationResultEnum(Enum):
        IDENTICAL = 0
        NOT_IDENTICAL = 1

    class SeverityScore_EvaluationResultEnum(Enum):
        IDENTICAL_WITH_NORMAL = 0
        IDENTICAL_WITH_RANGE_RANGE = 1
        NOT_IDENTICAL = 2

    class Equality_EvaluationResultEnum(Enum):
        E_LABEL = 0
        T_LABEL = 1
        U_LABEL = 2
        E_SCORE = 3
        T_SCORE = 4
        U_SCORE = 5
        E_RANGE_SCORE = 6
        T_RANGE_SCORE = 7
        U_RANGE_SCORE = 8
        UNEQUAL = 9

        def __str__(self) -> str:
            return f"{self.name}"

    def __init__(self):
        self.id = -1
        self.cwe_equality_status = None
        self.severity_label_equality_status = None
        self.severity_score_equality_status = None
        self.equality_status = None

    def analyze(self, raw_experiment_result):
        print(type(raw_experiment_result), len(raw_experiment_result))

        for raw_result in raw_experiment_result:
            self.id = raw_result['id']

            for radius in constants.ANALYSIS_RADIUS:
                pass
    # self.equal_severity = (self.llm_output['severity'] is not None and
    #                        len(self.ground_truth_severities) > 0 and
    #                        str(self.llm_output['severity']).lower() == str(
    #             self.ground_truth_severities[self.ground_truth_CVSS_version[0]]).lower())
    #
    # self.cwe_evaluation = self.calculate_cwe_evaluation(self.llm_output['CWE_IDS'], self.ground_truth_CWEs)
    # self.is_equal = ((self.equal_severity) and
    #                  (self.cwe_evaluation == EvaluationResult.CWE_EvaluationResultEnum.IDENTICAL))

    # def calculate_cwe_evaluation(self, predicted_CWEs: list, ground_truth_CWEs: list) :
    #     predicted_CWEs_set = set(predicted_CWEs)
    #     ground_truth_CWEs_set = set(ground_truth_CWEs)
    #
    #     if len(predicted_CWEs_set) == 0:
    #         return ExperimentResult.CWE_EvaluationResultEnum.EMPTY_PR
    #     elif predicted_CWEs_set == ground_truth_CWEs_set:
    #         return ExperimentResult.CWE_EvaluationResultEnum.IDENTICAL
    #     elif ground_truth_CWEs_set.issubset(predicted_CWEs_set):
    #         return ExperimentResult.CWE_EvaluationResultEnum.GT_SUBSET_OF_PR
    #     elif predicted_CWEs_set.issubset(ground_truth_CWEs_set):
    #         return ExperimentResult.CWE_EvaluationResultEnum.PR_SUBSET_OF_GT
    #     elif ground_truth_CWEs_set.isdisjoint(predicted_CWEs_set):
    #         return ExperimentResult.CWE_EvaluationResultEnum.NOT_OVERLAPPED
    #     return ExperimentResult.CWE_EvaluationResultEnum.OVERLAPPED

    # @staticmethod
    # def analyze_evaluations(evaluations: list[dict]):
    #     equal_counter = 0
    #     errors_counter = 0
    #     cwe_identical_counter = 0
    #     cwe_gt_subset_of_pr_counter = 0
    #     cwe_pr_subset_of_gt_counter = 0
    #     cwe_empty_pr_counter = 0
    #     cwe_non_overlapped_counter = 0
    #     cwe_overlapped_counter = 0
    #     equal_severity_counter = 0
    #     invalid_inference_counter = 0
    #
    #     for evaluation in evaluations:
    #         if evaluation['error_msg'] is not None:
    #             errors_counter += 1
    #         else:
    #             if evaluation['is_equal']:
    #                 equal_counter += 1
    #             if evaluation['equal_severity'] is True:
    #                 equal_severity_counter += 1
    #             if evaluation['llm_output'] is None:
    #                 invalid_inference_counter += 1
    #             if evaluation['cwe_evaluation'] == "IDENTICAL":
    #                 cwe_identical_counter += 1
    #             elif evaluation['cwe_evaluation'] == "GT_SUBSET_OF_PR":
    #                 cwe_gt_subset_of_pr_counter += 1
    #             elif evaluation['cwe_evaluation'] == "PR_SUBSET_OF_GT":
    #                 cwe_pr_subset_of_gt_counter += 1
    #             elif evaluation['cwe_evaluation'] == "EMPTY_PR":
    #                 cwe_empty_pr_counter += 1
    #             elif evaluation['cwe_evaluation'] == "NOT_OVERLAPPED":
    #                 cwe_non_overlapped_counter += 1
    #             elif evaluation['cwe_evaluation'] == "OVERLAPPED":
    #                 cwe_overlapped_counter += 1
    #
    #     return {
    #         'total_number_of_samples': len(evaluations),
    #         'timestamp': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    #         'errors': errors_counter,
    #         'equal': equal_counter,
    #         'accuracy_overall': 0 if len(evaluations) == 0 else (100.0 * equal_counter / len(evaluations)),
    #         'accuracy_CWE': 0 if len(evaluations) == 0 else 100.0 * cwe_identical_counter / len(evaluations),
    #         'accuracy_severity': 0 if len(evaluations) == 0 else 100.0 * equal_severity_counter / len(evaluations),
    #         'CWE_identical': cwe_identical_counter,
    #         'CWE_gt_subset_of_pr': cwe_gt_subset_of_pr_counter,
    #         'CWE_pr_subset_of_gt': cwe_pr_subset_of_gt_counter,
    #         'CWE_empty_pr': cwe_empty_pr_counter,
    #         'CWE_non_overlapped': cwe_non_overlapped_counter,
    #         'CWE_overlapped': cwe_overlapped_counter,
    #         'equal_severities': equal_severity_counter,
    #         'invalid_inferences': invalid_inference_counter,
    #         'evaluations': evaluations}
