import datetime
from enum import Enum

import constants


class CWE_EvaluationResultEnum(Enum):
    IDENTICAL = 0
    GT_SUBSET_OF_PR = 1
    PR_SUBSET_OF_GT = 2
    EMPTY_PR = 3
    NOT_OVERLAPPED = 4
    OVERLAPPED = 5

    def __str__(self) -> str:
        return f"{self.name}"


class SeverityLabel_EvaluationResultEnum(Enum):
    IDENTICAL = 0
    NOT_IDENTICAL = 1

    def __str__(self) -> str:
        return f"{self.name}"


class SeverityScore_EvaluationResultEnum(Enum):
    IDENTICAL_EXACT_MATCH = 0
    IDENTICAL_IN_LABEL_RANGE = 1
    IDENTICAL_IN_RADIUS_RANGE = 2
    NOT_IDENTICAL = 3

    def __str__(self) -> str:
        return f"{self.name}"


class Equality_EvaluationResultEnum(Enum):
    E_LABEL = 0
    T_LABEL = 1
    U_LABEL = 2
    E_SCORE = 3
    T_SCORE = 4
    U_SCORE = 5
    E_LABEL_RANGE_SCORE = 6
    T_LABEL_RANGE_SCORE = 7
    U_LABEL_RANGE_SCORE = 8
    E_RADIUS_RANGE_SCORE = 9
    T_RADIUS_RANGE_SCORE = 10
    U_RADIUS_RANGE_SCORE = 11
    UNEQUAL = 12

    def __str__(self) -> str:
        return f"{self.name}"


class Evaluator:

    def __init__(self):
        self.reference_id = -1
        self.cwe_equality_status = {'E': None, 'T': None, 'U': None}
        self.severity_label_equality_status = None
        self.severity_score_equality_status = None

    def analyze(self, raw_experiment_result):
        ERROR_counter = 0
        EQUAL_E_LABEL_counter = 0  # todo count all these
        EQUAL_T_LABEL_counter = 0
        EQUAL_U_LABEL_counter = 0
        EQUAL_E_SCORE_counter = 0
        EQUAL_T_SCORE_counter = 0
        EQUAL_U_SCORE_counter = 0
        EQUAL_E_LABEL_RANGE_counter = 0  # MEANS THE ALLOWED RANGE OF THE SCORE FOR THE SAME LABEL
        EQUAL_T_LABEL_RANGE_counter = 0
        EQUAL_U_LABEL_RANGE_counter = 0
        EQUAL_E_RADIUS_RANGE_counter = 0
        EQUAL_T_RADIUS_RANGE_counter = 0
        EQUAL_U_RADIUS_RANGE_counter = 0
        E_IDENTICAL_CWE_counter = 0
        T_IDENTICAL_CWE_counter = 0
        U_IDENTICAL_CWE_counter = 0
        GT_SUBSET_OF_E_counter = 0
        GT_SUBSET_OF_T_counter = 0
        GT_SUBSET_OF_U_counter = 0
        E_SUBSET_OF_GT_counter = 0
        T_SUBSET_OF_GT_counter = 0
        U_SUBSET_OF_GT_counter = 0
        EMPTY_E_counter = 0
        EMPTY_T_counter = 0
        EMPTY_U_counter = 0
        NON_OVERLAPPED_E_counter = 0
        NON_OVERLAPPED_T_counter = 0
        NON_OVERLAPPED_U_counter = 0
        OVERLAPPED_E_counter = 0
        OVERLAPPED_T_counter = 0
        OVERLAPPED_U_counter = 0
        SEVERITY_LABEL_EQUAL_LABEL_counter = 0
        SEVERITY_LABEL_EQUAL_SCORE_EXATCT_MATCH_counter = 0
        SEVERITY_LABEL_EQUAL_SCORE_LABEL_RANGE_counter = 0
        SEVERITY_LABEL_EQUAL_SCORE_RADIUS_RANGE_counter = 0
        INVALID_INFERENCE_counter = 0

        for raw_result in raw_experiment_result:
            self.reference_id = raw_result['id']
            if raw_result['error_msg'] is not None:
                ERROR_counter += 1
            else:
                #####       LABEL ANALYSIS       #####
                gt_CVSS = raw_result['ground_truth_CVSS_version'][0]
                gt_label = raw_result['ground_truth_severities'][gt_CVSS][0]
                predicted_label = raw_result['llm_output']['SEVERITY_LABEL']

                if (predicted_label is not None) and (str(predicted_label).lower() == str(gt_label).lower()):
                    self.severity_label_equality_status = SeverityLabel_EvaluationResultEnum.IDENTICAL
                else:
                    self.severity_label_equality_status = SeverityLabel_EvaluationResultEnum.NOT_IDENTICAL

                gt_score = float(raw_result['ground_truth_severities'][gt_CVSS][1])
                predicted_score = float(raw_result['llm_output']['SEVERITY_SCORE'])

                score_evaluated = False
                if gt_score == predicted_score:
                    self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH
                    score_evaluated = True

                #######      SCORE ANALYSIS     ####### (OBVIOUSLY IF LABEL IS IDENTICAL, THE SCORE WOULD AUTOMATICALLY BE EITHER EXACT MATCH OR IN_LABEL_RANGE. OTHERWISE SOMETHING IS WRONG IN MY CODE)
                for radius in constants.ANALYSIS_RADIUS:
                    if not score_evaluated:
                        label_range = constants.SEVERITY_SCORE_RANGES[gt_CVSS][gt_label]

                        if label_range[0] <= predicted_score <= label_range[1]:
                            self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_IN_LABEL_RANGE
                        else:
                            radius_range = (max(label_range[0], predicted_score - radius),
                                            min(label_range[1], predicted_score + radius))

                            if radius_range[0] <= predicted_score <= radius_range[1]:
                                self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_IN_RADIUS_RANGE
                            else:
                                self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.NOT_IDENTICAL
                    #########################################
                #######   CWE EVALUATION   #######
                GT_CWEs = set(raw_result['ground_truth_CWEs'])

                ## FIRST: E
                E = set(raw_result['llm_output']['EXACT_CWE_IDS'])
                self.cwe_equality_status['E'] = self.evaluate_cwe(E, GT_CWEs)
                ## SECOND: T
                T = set(raw_result['llm_output']['TOP_FIVE_CWE_IDS'])
                self.cwe_equality_status['T'] = self.evaluate_cwe(T, GT_CWEs)
                ## THIRD: EUT
                E_U_T = E | T
                self.cwe_equality_status['U'] = self.evaluate_cwe(E_U_T, GT_CWEs)

        return {
            'TOTAL_NUMBER_OF_SAMPLES_counter': len(raw_experiment_result),
            'timestamp': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'ERRORS': ERROR_counter,
            'EQUAL_E_LABEL_counter': EQUAL_E_LABEL_counter,
            'EQUAL_T_LABEL_counter': EQUAL_T_LABEL_counter,
            'EQUAL_U_LABEL_counter': EQUAL_U_LABEL_counter,
            'EQUAL_E_SCORE_counter': EQUAL_E_SCORE_counter,
            'EQUAL_T_SCORE_counter': EQUAL_T_SCORE_counter,
            'EQUAL_U_SCORE_counter': EQUAL_U_SCORE_counter,

            'EQUAL_E_LABEL_RANGE_counter': EQUAL_E_LABEL_RANGE_counter,
            'EQUAL_T_LABEL_RANGE_counter': EQUAL_T_LABEL_RANGE_counter,
            'EQUAL_U_LABEL_RANGE_counter': EQUAL_U_LABEL_RANGE_counter,
            'EQUAL_E_RADIUS_RANGE_counter': EQUAL_E_RADIUS_RANGE_counter,
            'EQUAL_T_RADIUS_RANGE_counter': EQUAL_T_RADIUS_RANGE_counter,
            'EQUAL_U_RADIUS_RANGE_counter': EQUAL_U_RADIUS_RANGE_counter,

            'E_IDENTICAL_CWE_counter': E_IDENTICAL_CWE_counter,
            'T_IDENTICAL_CWE_counter': T_IDENTICAL_CWE_counter,
            'U_IDENTICAL_CWE_counter': U_IDENTICAL_CWE_counter,
            'GT_SUBSET_OF_E_counter': GT_SUBSET_OF_E_counter,
            'GT_SUBSET_OF_T_counter': GT_SUBSET_OF_T_counter,
            'GT_SUBSET_OF_U_counter': GT_SUBSET_OF_U_counter,
            'E_SUBSET_OF_GT_counter': E_SUBSET_OF_GT_counter,
            'T_SUBSET_OF_GT_counter': T_SUBSET_OF_GT_counter,
            'U_SUBSET_OF_GT_counter': U_SUBSET_OF_GT_counter,
            'EMPTY_E_counter': EMPTY_E_counter,
            'EMPTY_T_counter': EMPTY_T_counter,
            'EMPTY_U_counter': EMPTY_U_counter,
            'NON_OVERLAPPED_E_counter': NON_OVERLAPPED_E_counter,
            'NON_OVERLAPPED_T_counter': NON_OVERLAPPED_T_counter,
            'NON_OVERLAPPED_U_counter': NON_OVERLAPPED_U_counter,
            'OVERLAPPED_E_counter': OVERLAPPED_E_counter,
            'OVERLAPPED_T_counter': OVERLAPPED_T_counter,
            'OVERLAPPED_U_counter': OVERLAPPED_U_counter,
            'SEVERITY_LABEL_EQUAL_LABEL_counter': SEVERITY_LABEL_EQUAL_LABEL_counter,
            'SEVERITY_LABEL_EQUAL_SCORE_EXATCT_MATCH_counter': SEVERITY_LABEL_EQUAL_SCORE_EXATCT_MATCH_counter,
            'SEVERITY_LABEL_EQUAL_SCORE_LABEL_RANGE_counter': SEVERITY_LABEL_EQUAL_SCORE_LABEL_RANGE_counter,
            'SEVERITY_LABEL_EQUAL_SCORE_RADIUS_RANGE_counter': SEVERITY_LABEL_EQUAL_SCORE_RADIUS_RANGE_counter,
            'accuracy_overall_E_LABEL': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_E_LABEL_counter / len(raw_experiment_result)),
            'accuracy_overall_T_LABEL': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_T_LABEL_counter / len(raw_experiment_result)),
            'accuracy_overall_U_LABEL': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_U_LABEL_counter / len(raw_experiment_result)),
            'accuracy_overall_E_SCORE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_E_SCORE_counter / len(raw_experiment_result)),
            'accuracy_overall_T_SCORE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_T_SCORE_counter / len(raw_experiment_result)),
            'accuracy_overall_U_SCORE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_U_SCORE_counter / len(raw_experiment_result)),
            'accuracy_overall_E_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_E_LABEL_RANGE_counter / len(raw_experiment_result)),
            'accuracy_overall_T_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_T_LABEL_RANGE_counter / len(raw_experiment_result)),
            'accuracy_overall_U_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_U_LABEL_RANGE_counter / len(raw_experiment_result)),
            'accuracy_overall_E_RADIUS_RANGE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_E_RADIUS_RANGE_counter / len(raw_experiment_result)),
            'accuracy_overall_T_RADIUS_RANGE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_T_RADIUS_RANGE_counter / len(raw_experiment_result)),
            'accuracy_overall_U_RADIUS_RANGE': 0 if len(raw_experiment_result) == 0 else (
                        100.0 * EQUAL_U_RADIUS_RANGE_counter / len(raw_experiment_result)),
            'accuracy_CWE_E': 0 if len(raw_experiment_result) == 0 else 100.0 * E_IDENTICAL_CWE_counter / len(
                raw_experiment_result),
            'accuracy_CWE_T': 0 if len(raw_experiment_result) == 0 else 100.0 * T_IDENTICAL_CWE_counter / len(
                raw_experiment_result),
            'accuracy_CWE_U': 0 if len(raw_experiment_result) == 0 else 100.0 * U_IDENTICAL_CWE_counter / len(
                raw_experiment_result),
            'accuracy_severity_label': 0 if len(
                raw_experiment_result) == 0 else 100.0 * SEVERITY_LABEL_EQUAL_LABEL_counter / len(
                raw_experiment_result),
            'accuracy_severity_score_exact_match': 0 if len(
                raw_experiment_result) == 0 else 100.0 * SEVERITY_LABEL_EQUAL_SCORE_EXATCT_MATCH_counter / len(
                raw_experiment_result),
            'accuracy_severity_score_label_range': 0 if len(
                raw_experiment_result) == 0 else 100.0 * SEVERITY_LABEL_EQUAL_SCORE_LABEL_RANGE_counter / len(
                raw_experiment_result),
            'accuracy_severity_score_radius_range': 0 if len(
                raw_experiment_result) == 0 else 100.0 * SEVERITY_LABEL_EQUAL_SCORE_RADIUS_RANGE_counter / len(
                raw_experiment_result),
            ##
            'INVALID_INFERENCES_counter': INVALID_INFERENCE_counter}

    def evaluate_cwe(self, predicted_CWEs: set, GT_CWEs: set):
        if len(predicted_CWEs) == 0:
            return CWE_EvaluationResultEnum.EMPTY_PR
        elif predicted_CWEs == GT_CWEs:
            return CWE_EvaluationResultEnum.IDENTICAL
        elif GT_CWEs.issubset(predicted_CWEs):
            return CWE_EvaluationResultEnum.GT_SUBSET_OF_PR
        elif predicted_CWEs.issubset(GT_CWEs):
            return CWE_EvaluationResultEnum.PR_SUBSET_OF_GT
        elif predicted_CWEs.isdisjoint(GT_CWEs):
            return CWE_EvaluationResultEnum.NOT_OVERLAPPED
        else:
            return CWE_EvaluationResultEnum.OVERLAPPED
