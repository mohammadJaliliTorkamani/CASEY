import datetime
from enum import Enum

import constants


class CWE_EvaluationResultEnum(str, Enum):
    IDENTICAL = 0
    GT_SUBSET_OF_PR = 1
    PR_SUBSET_OF_GT = 2
    EMPTY_PR = 3
    NOT_OVERLAPPED = 4
    OVERLAPPED = 5

    def __str__(self) -> str:
        return f"{self.name}"


class SeverityLabel_EvaluationResultEnum(str, Enum):
    IDENTICAL = 0
    NOT_IDENTICAL = 1

    def __str__(self) -> str:
        return f"{self.name}"


class SeverityScore_EvaluationResultEnum(str, Enum):
    IDENTICAL_EXACT_MATCH = 0
    IDENTICAL_IN_LABEL_RANGE = 1
    IDENTICAL_IN_RADIUS_RANGE = 2
    NOT_IDENTICAL = 3

    def __str__(self) -> str:
        return f"{self.name}"


class Equality_EvaluationResultEnum(str, Enum):
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
        self.severity_score_equality_status = (None, None)  # The first is type, the second is extra info
        # (used for radius range for min acceptable radius in the prefixed radius list)

    def analyze(self, raw_experiment_result):
        metrics = {
            'ERROR_counter': 0,
            'EQUAL_E_LABEL_counter': 0,
            'EQUAL_T_LABEL_counter': 0,
            'EQUAL_U_LABEL_counter': 0,
            'EQUAL_E_SCORE_counter': 0,
            'EQUAL_T_SCORE_counter': 0,
            'EQUAL_U_SCORE_counter': 0,
            'EQUAL_E_LABEL_RANGE_counter': 0,  # MEANS THE ALLOWED RANGE OF THE SCORE FOR THE SAME LABEL   #####
            'EQUAL_T_LABEL_RANGE_counter': 0,
            'EQUAL_U_LABEL_RANGE_counter': 0,
            'EQUAL_E_RADIUS_RANGE_counter': 0,
            'EQUAL_T_RADIUS_RANGE_counter': 0,
            'EQUAL_U_RADIUS_RANGE_counter': 0,
            'E_IDENTICAL_CWE_counter': 0,
            'T_IDENTICAL_CWE_counter': 0,
            'U_IDENTICAL_CWE_counter': 0,
            'GT_SUBSET_OF_E_counter': 0,
            'GT_SUBSET_OF_T_counter': 0,
            'GT_SUBSET_OF_U_counter': 0,
            'E_SUBSET_OF_GT_counter': 0,
            'T_SUBSET_OF_GT_counter': 0,
            'U_SUBSET_OF_GT_counter': 0,
            'EMPTY_E_counter': 0,
            'EMPTY_T_counter': 0,
            'EMPTY_U_counter': 0,
            'NON_OVERLAPPED_E_counter': 0,
            'NON_OVERLAPPED_T_counter': 0,
            'NON_OVERLAPPED_U_counter': 0,
            'OVERLAPPED_E_counter': 0,
            'OVERLAPPED_T_counter': 0,
            'OVERLAPPED_U_counter': 0,
            'SEVERITY_LABEL_EQUAL_LABEL_counter': 0,  ######
            'SEVERITY_EQUAL_SCORE_EXACT_MATCH_counter': 0,
            'SEVERITY_EQUAL_SCORE_LABEL_RANGE_counter': 0,
            'SEVERITY_EQUAL_SCORE_RADIUS_RANGE_counter': 0,
            'INVALID_INFERENCE_counter': 0
        }

        evaluations = list()

        for raw_result in raw_experiment_result:
            self.reset_properties()
            self.reference_id = raw_result['id']
            if raw_result['error_msg'] is not None:
                metrics['ERROR_counter'] += 1
            else:
                if raw_result['llm_output'] is None:
                    metrics['INVALID_INFERENCE_counter'] += 1
                    evaluations.append(self.toJson())
                    continue

                #####       LABEL ANALYSIS       #####
                gt_CVSS = raw_result['ground_truth_CVSS_version'][0]
                gt_label = raw_result['ground_truth_severities'][gt_CVSS][0]
                predicted_label = raw_result['llm_output']['SEVERITY_LABEL']

                if predicted_label is None:
                    self.severity_label_equality_status = None
                elif str(predicted_label).lower() == str(gt_label).lower():
                    self.severity_label_equality_status = SeverityLabel_EvaluationResultEnum.IDENTICAL
                    metrics['SEVERITY_LABEL_EQUAL_LABEL_counter'] += 1
                else:
                    self.severity_label_equality_status = SeverityLabel_EvaluationResultEnum.NOT_IDENTICAL

                gt_score = float(raw_result['ground_truth_severities'][gt_CVSS][1])
                predicted_score = float(raw_result['llm_output']['SEVERITY_SCORE'])

                if predicted_score == -1:
                    self.severity_score_equality_status = None, None
                elif gt_score == predicted_score:
                    self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH, None
                    metrics['SEVERITY_EQUAL_SCORE_EXACT_MATCH_counter'] += 1

                #######      SCORE ANALYSIS     ####### (OBVIOUSLY IF LABEL IS IDENTICAL, THE SCORE WOULD AUTOMATICALLY BE EITHER EXACT MATCH OR IN_LABEL_RANGE. OTHERWISE SOMETHING IS WRONG IN MY CODE)
                else:
                    label_range = constants.SEVERITY_SCORE_RANGES[gt_CVSS][gt_label]
                    if label_range[0] <= predicted_score <= label_range[1]:
                        self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_IN_LABEL_RANGE, None
                        metrics['SEVERITY_EQUAL_SCORE_LABEL_RANGE_counter'] += 1
                    else:
                        for radius in sorted(constants.ANALYSIS_RADIUS):
                            radius_range = (predicted_score - radius, predicted_score + radius)
                            in_range = radius_range[0] <= gt_score <= radius_range[1]

                            if in_range:
                                self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_IN_RADIUS_RANGE, radius
                                metrics['SEVERITY_EQUAL_SCORE_RADIUS_RANGE_counter'] += 1
                                break
                            else:
                                self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.NOT_IDENTICAL, None

                #######   CWE EVALUATION   #######
                GT_CWEs = set(raw_result['ground_truth_CWEs'])

                ## FIRST: E
                E = set(raw_result['llm_output']['EXACT_CWE_IDS'])
                self.cwe_equality_status['E'], metric_to_add_key = self.evaluate_cwe(E, 'E', GT_CWEs)
                metrics[metric_to_add_key] += 1
                if metric_to_add_key == 'E_IDENTICAL_CWE_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_E_LABEL_counter'] += 1
                    if self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['EQUAL_E_SCORE_counter'] += 1
                    elif self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_IN_LABEL_RANGE:
                        metrics['EQUAL_E_LABEL_RANGE_counter'] += 1
                    elif self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_IN_RADIUS_RANGE:
                        metrics['EQUAL_E_RADIUS_RANGE_counter'] += 1

                ## SECOND: T
                T = set(raw_result['llm_output']['TOP_FIVE_CWE_IDS'])
                self.cwe_equality_status['T'], metric_to_add_key = self.evaluate_cwe(T, 'T', GT_CWEs)

                metrics[metric_to_add_key] += 1
                if metric_to_add_key == 'T_IDENTICAL_CWE_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_T_LABEL_counter'] += 1
                    if self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['EQUAL_T_SCORE_counter'] += 1
                    elif self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_IN_LABEL_RANGE:
                        metrics['EQUAL_T_LABEL_RANGE_counter'] += 1
                    elif self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_IN_RADIUS_RANGE:
                        metrics['EQUAL_T_RADIUS_RANGE_counter'] += 1

                ## THIRD: EUT
                E_U_T = E | T
                self.cwe_equality_status['U'], metric_to_add_key = self.evaluate_cwe(E_U_T, 'U', GT_CWEs)
                metrics[metric_to_add_key] += 1
                if metric_to_add_key == 'U_IDENTICAL_CWE_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_U_LABEL_counter'] += 1
                    if self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['EQUAL_U_SCORE_counter'] += 1
                    elif self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_IN_LABEL_RANGE:
                        metrics['EQUAL_U_LABEL_RANGE_counter'] += 1
                    elif self.severity_score_equality_status[
                        0] == SeverityScore_EvaluationResultEnum.IDENTICAL_IN_RADIUS_RANGE:
                        metrics['EQUAL_U_RADIUS_RANGE_counter'] += 1

            evaluations.append(self.toJson())

        return {
            'TOTAL_NUMBER_OF_SAMPLES_counter': len(raw_experiment_result),  #
            'timestamp': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),  #

            'accuracy_overall_E_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_U_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_U_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_E_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_U_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_U_SCORE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_E_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_LABEL_RANGE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_LABEL_RANGE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_U_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_U_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_E_RADIUS_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_RADIUS_RANGE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_RADIUS_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_RADIUS_RANGE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_U_RADIUS_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_U_RADIUS_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_identical_CWE_E': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'E_IDENTICAL_CWE_counter'] / len(
                raw_experiment_result),
            'accuracy_identical_CWE_T': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'T_IDENTICAL_CWE_counter'] / len(
                raw_experiment_result),
            'accuracy_identical_CWE_U': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'U_IDENTICAL_CWE_counter'] / len(
                raw_experiment_result),

            'accuracy_identical_severity_label': 0 if len(
                raw_experiment_result) == 0 else 100.0 * metrics['SEVERITY_LABEL_EQUAL_LABEL_counter'] / len(
                raw_experiment_result),

            'accuracy_severity_score_exact_match': 0 if len(
                raw_experiment_result) == 0 else 100.0 * metrics[
                'SEVERITY_EQUAL_SCORE_EXACT_MATCH_counter'] / len(
                raw_experiment_result),
            'accuracy_severity_score_label_range': 0 if len(
                raw_experiment_result) == 0 else 100.0 * metrics[
                'SEVERITY_EQUAL_SCORE_LABEL_RANGE_counter'] / len(
                raw_experiment_result),

            'accuracy_severity_score_radius_range': 0 if len(
                raw_experiment_result) == 0 else 100.0 * metrics[
                'SEVERITY_EQUAL_SCORE_RADIUS_RANGE_counter'] / len(
                raw_experiment_result),

            'ERRORS': metrics['ERROR_counter'],  #
            'EQUAL_E_LABEL_counter': metrics['EQUAL_E_LABEL_counter'],
            'EQUAL_T_LABEL_counter': metrics['EQUAL_T_LABEL_counter'],
            'EQUAL_U_LABEL_counter': metrics['EQUAL_U_LABEL_counter'],

            'EQUAL_E_SCORE_MATCH_counter': metrics['EQUAL_E_SCORE_counter'],
            'EQUAL_T_SCORE_MATCH_counter': metrics['EQUAL_T_SCORE_counter'],
            'EQUAL_U_SCORE_MATCH_counter': metrics['EQUAL_U_SCORE_counter'],

            'EQUAL_E_LABEL_RANGE_counter': metrics['EQUAL_E_LABEL_RANGE_counter'],
            'EQUAL_T_LABEL_RANGE_counter': metrics['EQUAL_T_LABEL_RANGE_counter'],
            'EQUAL_U_LABEL_RANGE_counter': metrics['EQUAL_U_LABEL_RANGE_counter'],

            'EQUAL_E_RADIUS_RANGE_counter': metrics['EQUAL_E_RADIUS_RANGE_counter'],
            'EQUAL_T_RADIUS_RANGE_counter': metrics['EQUAL_T_RADIUS_RANGE_counter'],
            'EQUAL_U_RADIUS_RANGE_counter': metrics['EQUAL_U_RADIUS_RANGE_counter'],

            'SEVERITY_LABEL_EQUAL_LABEL_counter': metrics['SEVERITY_LABEL_EQUAL_LABEL_counter'],

            'SEVERITY_EQUAL_SCORE_EXACT_MATCH_counter': metrics['SEVERITY_EQUAL_SCORE_EXACT_MATCH_counter'],
            'SEVERITY_EQUAL_SCORE_LABEL_RANGE_counter': metrics['SEVERITY_EQUAL_SCORE_LABEL_RANGE_counter'],
            'SEVERITY_EQUAL_SCORE_RADIUS_RANGE_counter': metrics['SEVERITY_EQUAL_SCORE_RADIUS_RANGE_counter'],

            'CWE_IDENTICAL_E_counter': metrics['E_IDENTICAL_CWE_counter'],  #
            'CWE_IDENTICAL_T_counter': metrics['T_IDENTICAL_CWE_counter'],  #
            'CWE_IDENTICAL_U_counter': metrics['U_IDENTICAL_CWE_counter'],  #

            'CSE_GT_SUBSET_OF_E_counter': metrics['GT_SUBSET_OF_E_counter'],  #
            'CWE_GT_SUBSET_OF_T_counter': metrics['GT_SUBSET_OF_T_counter'],  #
            'CWE_GT_SUBSET_OF_U_counter': metrics['GT_SUBSET_OF_U_counter'],  #

            'CWE_E_SUBSET_OF_GT_counter': metrics['E_SUBSET_OF_GT_counter'],  #
            'CWE_T_SUBSET_OF_GT_counter': metrics['T_SUBSET_OF_GT_counter'],  #
            'CWE_U_SUBSET_OF_GT_counter': metrics['U_SUBSET_OF_GT_counter'],  #

            'CWE_EMPTY_E_counter': metrics['EMPTY_E_counter'],  #
            'CWE_EMPTY_T_counter': metrics['EMPTY_T_counter'],  #
            'CWE_EMPTY_U_counter': metrics['EMPTY_U_counter'],  #

            'CWE_NON_OVERLAPPED_E_counter': metrics['NON_OVERLAPPED_E_counter'],  #
            'CWE_NON_OVERLAPPED_T_counter': metrics['NON_OVERLAPPED_T_counter'],  #
            'CWE_NON_OVERLAPPED_U_counter': metrics['NON_OVERLAPPED_U_counter'],  #

            'CWE_OVERLAPPED_E_counter': metrics['OVERLAPPED_E_counter'],  #
            'CWE_OVERLAPPED_T_counter': metrics['OVERLAPPED_T_counter'],  #
            'CWE_OVERLAPPED_U_counter': metrics['OVERLAPPED_U_counter'],  #

            'INVALID_INFERENCES_counter': metrics['INVALID_INFERENCE_counter'],
            'evaluations': evaluations}

    def evaluate_cwe(self, predicted_CWEs: set, predicted_CWEs_type: str, GT_CWEs: set) -> (
            tuple[CWE_EvaluationResultEnum, str]):
        if len(predicted_CWEs) == 0:
            return CWE_EvaluationResultEnum.EMPTY_PR, f"EMPTY_{predicted_CWEs_type}_counter"
        elif predicted_CWEs == GT_CWEs:
            return CWE_EvaluationResultEnum.IDENTICAL, f"{predicted_CWEs_type}_IDENTICAL_CWE_counter"
        elif GT_CWEs.issubset(predicted_CWEs):
            return CWE_EvaluationResultEnum.GT_SUBSET_OF_PR, f"GT_SUBSET_OF_{predicted_CWEs_type}_counter"
        elif predicted_CWEs.issubset(GT_CWEs):
            return CWE_EvaluationResultEnum.PR_SUBSET_OF_GT, f"{predicted_CWEs_type}_SUBSET_OF_GT_counter"
        elif predicted_CWEs.isdisjoint(GT_CWEs):
            return CWE_EvaluationResultEnum.NOT_OVERLAPPED, f"NON_OVERLAPPED_{predicted_CWEs_type}_counter"
        else:
            return CWE_EvaluationResultEnum.OVERLAPPED, f"OVERLAPPED_{predicted_CWEs_type}_counter"

    def toJson(self):
        return {
            'reference_id': self.reference_id,
            'cwe_equality_status': {k: (str(v) if isinstance(v, Enum) else v) for k, v in
                                    self.cwe_equality_status.items()},
            'severity_label_equality_status': None if self.severity_label_equality_status is None else str(
                self.severity_label_equality_status),
            'severity_score_equality_status': {'type': None if self.severity_score_equality_status[0] is None else str(
                self.severity_score_equality_status[0]),
                                               'load': self.severity_score_equality_status[1]}
        }

    def reset_properties(self):
        self.reference_id = -1
        self.cwe_equality_status = {'E': None, 'T': None, 'U': None}
        self.severity_label_equality_status = None
        self.severity_score_equality_status = (None, None)
