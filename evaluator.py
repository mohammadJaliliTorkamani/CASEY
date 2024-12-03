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
    NOT_IDENTICAL = 1

    def __str__(self) -> str:
        return f"{self.name}"


class SeverityScoreLabelRange_EvaluationResultEnum(str, Enum):
    IDENTICAL = 0
    NOT_IDENTICAL = 1

    def __str__(self) -> str:
        return f"{self.name}"


class SeverityScoreAsRadius_EvaluationResultEnum(str, Enum):
    COVERS = 0
    NOT_COVERS = 1

    def __str__(self) -> str:
        return f"{self.name}"


def get_empty_radius_score_dic():
    d = dict()
    for r in constants.ANALYSIS_RADIUS:
        d[r] = 0
    return d


def get_sum_of_value(d: dict):
    return sum(d.values())


class Evaluator:

    def __init__(self):
        self.reference_id = -1
        self.ground_truth_CWEs = -1
        self.ground_truth_severities = -1
        self.severity_llm_output = -1
        self.cwe_llm_output = -1

        self.valid_evaluation = None  # meaning that the inference is neither none nor has error(s)
        self.cwe_equality_status = {'E': None, 'T': None}
        self.severity_label_equality_status = None
        self.severity_score_equality_status = None
        self.severity_score_label_range_equality_status = (
            None, None)  # The first is type, the second is extra info (range)
        self.severity_score_equality_radius_status = (
            None, None)  # The first is type, the second is extra info (min radius)
        # (used for radius range for min acceptable radius in the prefixed radius list)

    def analyze(self, raw_experiment_result):
        metrics = {
            'SEVERITY_ERROR_counter': 0,
            'CWE_ERROR_counter': 0,
            'INVALID_SEVERITY_INFERENCE_counter': 0,
            'INVALID_CWE_INFERENCE_counter': 0,
            'EQUAL_E_EQUAL_LABEL_counter': 0,
            'EQUAL_E_EQUAL_SCORE_counter': 0,
            'EQUAL_E_WITHIN_LABEL_RANGE_counter': 0,
            'EQUAL_T_EQUAL_LABEL_counter': 0,
            'EQUAL_T_EQUAL_SCORE_counter': 0,
            'EQUAL_T_WITHIN_LABEL_RANGE_counter': 0,
            'EQUAL_T_WITHIN_RADIUS_RANGE_counter': 0,
            'GT_SUBSET_OF_E_EQUAL_LABEL_counter': 0,
            'GT_SUBSET_OF_E_EQUAL_SCORE_counter': 0,
            'GT_SUBSET_OF_E_WITHIN_LABEL_RANGE_counter': 0,
            'GT_SUBSET_OF_T_EQUAL_LABEL_counter': 0,
            'GT_SUBSET_OF_T_EQUAL_SCORE_counter': 0,
            'GT_SUBSET_OF_T_WITHIN_LABEL_RANGE_counter': 0,
            'GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_counter': 0,
            'E_SUBSET_OF_GT_EQUAL_LABEL_counter': 0,
            'E_SUBSET_OF_GT_EQUAL_SCORE_counter': 0,
            'E_SUBSET_OF_GT_WITHIN_LABEL_RANGE_counter': 0,
            'T_SUBSET_OF_GT_EQUAL_LABEL_counter': 0,
            'T_SUBSET_OF_GT_EQUAL_SCORE_counter': 0,
            'T_SUBSET_OF_GT_WITHIN_LABEL_RANGE_counter': 0,
            'E_IDENTICAL_CWE_counter': 0,
            'T_IDENTICAL_CWE_counter': 0,
            'GT_SUBSET_OF_E_counter': 0,
            'GT_SUBSET_OF_T_counter': 0,
            'E_SUBSET_OF_GT_counter': 0,
            'T_SUBSET_OF_GT_counter': 0,
            'EMPTY_E_counter': 0,
            'EMPTY_T_counter': 0,
            'NON_OVERLAPPED_E_counter': 0,
            'NON_OVERLAPPED_T_counter': 0,
            'OVERLAPPED_E_counter': 0,
            'OVERLAPPED_T_counter': 0,
            'EQUAL_LABEL_counter': 0,
            'EQUAL_SCORE_counter': 0,
            'WITHIN_LABEL_RANGE_counter': 0,
            'WITHIN_RADIUS_RANGE_counter': get_empty_radius_score_dic()
        }

        evaluations = list()

        for raw_result in raw_experiment_result:
            self.reset_properties()
            self.reference_id = raw_result['id']
            self.ground_truth_CWEs = raw_result['ground_truth_CWEs']
            self.ground_truth_severities = raw_result['ground_truth_severities']
            self.severity_llm_output = raw_result['severity_llm_output']
            self.cwe_llm_output = raw_result['cwe_llm_output']

            if (raw_result['severity_error_msg'] is not None) or (raw_result['cwe_error_msg'] is not None):
                self.valid_evaluation = False
                if raw_result['severity_error_msg'] is not None:
                    metrics['SEVERITY_ERROR_counter'] += 1
                if raw_result['cwe_error_msg'] is not None:
                    metrics['CWE_ERROR_counter'] += 1
            else:
                if (raw_result['severity_llm_output'] is None) or (raw_result['cwe_llm_output'] is None):
                    self.valid_evaluation = False
                    if raw_result['severity_llm_output'] is None:
                        metrics['INVALID_SEVERITY_INFERENCE_counter'] += 1
                    if raw_result['CWE_llm_output'] is None:
                        metrics['INVALID_CWE_INFERENCE_counter'] += 1

                    evaluations.append(self.toJson())
                    continue

                #####       LABEL ANALYSIS       #####
                gt_CVSS = raw_result['ground_truth_CVSS_version'][0]
                gt_label = raw_result['ground_truth_severities'][gt_CVSS][0]
                predicted_label = raw_result['severity_llm_output']['SEVERITY_LABEL']

                if predicted_label is None:
                    self.severity_label_equality_status = None
                elif str(predicted_label).lower() == str(gt_label).lower():
                    self.severity_label_equality_status = SeverityLabel_EvaluationResultEnum.IDENTICAL
                    metrics['EQUAL_LABEL_counter'] += 1
                else:
                    self.severity_label_equality_status = SeverityLabel_EvaluationResultEnum.NOT_IDENTICAL

                #######      SCORE ANALYSIS     ####### (OBVIOUSLY IF LABEL IS IDENTICAL, THE SCORE WOULD AUTOMATICALLY BE EITHER EXACT MATCH OR IN_LABEL_RANGE. OTHERWISE SOMETHING IS WRONG IN MY CODE)

                gt_score = float(raw_result['ground_truth_severities'][gt_CVSS][1])
                predicted_score = float(raw_result['severity_llm_output']['SEVERITY_SCORE'])
                print("Predicated score: ", gt_score, predicted_score)
                label_range = constants.SEVERITY_SCORE_RANGES[gt_CVSS][gt_label]

                if predicted_score == -1:
                    self.severity_score_equality_status = None
                    self.severity_score_label_range_equality_status = None, None
                    self.severity_score_equality_radius_status = SeverityScoreAsRadius_EvaluationResultEnum.NOT_COVERS, None
                elif gt_score == predicted_score:
                    self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH
                    self.severity_score_label_range_equality_status = SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL, label_range
                    self.severity_score_equality_radius_status = SeverityScoreAsRadius_EvaluationResultEnum.COVERS, \
                        sorted(constants.ANALYSIS_RADIUS)[0]
                    metrics['EQUAL_SCORE_counter'] += 1
                    metrics['WITHIN_LABEL_RANGE_counter'] += 1
                    for radius in sorted(constants.ANALYSIS_RADIUS):
                        metrics['WITHIN_RADIUS_RANGE_counter'][radius] += 1

                else:
                    if label_range[0] <= predicted_score <= label_range[1]:
                        self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.NOT_IDENTICAL
                        self.severity_score_label_range_equality_status = SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL, label_range
                        metrics['WITHIN_LABEL_RANGE_counter'] += 1
                    else:
                        self.severity_score_equality_status = SeverityScore_EvaluationResultEnum.NOT_IDENTICAL
                        self.severity_score_label_range_equality_status = SeverityScoreLabelRange_EvaluationResultEnum.NOT_IDENTICAL, None

                    assigned = False
                    for radius in sorted(constants.ANALYSIS_RADIUS):
                        radius_range = (predicted_score - radius, predicted_score + radius)
                        in_range = radius_range[0] <= gt_score <= radius_range[1]

                        if in_range:
                            metrics['WITHIN_RADIUS_RANGE_counter'][radius] += 1
                            if not assigned:
                                self.severity_score_equality_radius_status = SeverityScoreAsRadius_EvaluationResultEnum.COVERS, radius
                                assigned = True
                        else:
                            if not assigned:
                                self.severity_score_equality_radius_status = SeverityScoreAsRadius_EvaluationResultEnum.NOT_COVERS, None

                #######   CWE EVALUATION   #######
                GT_CWEs = set(raw_result['ground_truth_CWEs'])

                ## FIRST: E
                E = set(raw_result['cwe_llm_output']['EXACT_CWE_IDS'])
                self.cwe_equality_status['E'], metric_to_add_key = self.evaluate_cwe(E, 'E', GT_CWEs)
                metrics[metric_to_add_key] += 1
                if metric_to_add_key == 'E_IDENTICAL_CWE_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_E_EQUAL_LABEL_counter'] += 1

                    if self.severity_score_equality_status == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['EQUAL_E_EQUAL_SCORE_counter'] += 1

                    if self.severity_score_label_range_equality_status[
                        0] == SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_E_WITHIN_LABEL_RANGE_counter'] += 1

                    if self.severity_score_equality_radius_status[
                        0] == SeverityScoreAsRadius_EvaluationResultEnum.COVERS:
                        for r in sorted(constants.ANALYSIS_RADIUS):
                            metrics.setdefault(f'EQUAL_E_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
                            if self.severity_score_equality_radius_status[1] <= r:
                                metrics[f'EQUAL_E_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 1
                            else:
                                metrics[
                                    f'EQUAL_E_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 0  # this creates it if not exists

                elif metric_to_add_key == 'GT_SUBSET_OF_E_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['GT_SUBSET_OF_E_EQUAL_LABEL_counter'] += 1
                    if self.severity_score_equality_status == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['GT_SUBSET_OF_E_EQUAL_SCORE_counter'] += 1
                    if self.severity_score_label_range_equality_status[
                        0] == SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL:
                        metrics['GT_SUBSET_OF_E_WITHIN_LABEL_RANGE_counter'] += 1

                    if self.severity_score_equality_radius_status[
                        0] == SeverityScoreAsRadius_EvaluationResultEnum.COVERS:
                        for r in sorted(constants.ANALYSIS_RADIUS):
                            metrics.setdefault(f'GT_SUBSET_OF_E_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
                            if self.severity_score_equality_radius_status[1] <= r:
                                metrics[f'GT_SUBSET_OF_E_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 1
                            else:
                                metrics[
                                    f'GT_SUBSET_OF_E_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 0  # this creates it if not exists


                elif metric_to_add_key == 'E_SUBSET_OF_GT_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['E_SUBSET_OF_GT_EQUAL_LABEL_counter'] += 1
                    if self.severity_score_equality_status == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['E_SUBSET_OF_GT_EQUAL_SCORE_counter'] += 1
                    if self.severity_score_label_range_equality_status[
                        0] == SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL:
                        metrics['E_SUBSET_OF_GT_WITHIN_LABEL_RANGE_counter'] += 1

                    if self.severity_score_equality_radius_status[
                        0] == SeverityScoreAsRadius_EvaluationResultEnum.COVERS:
                        for r in sorted(constants.ANALYSIS_RADIUS):
                            metrics.setdefault(f'E_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
                            if self.severity_score_equality_radius_status[1] <= r:
                                metrics[f'E_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 1
                            else:
                                metrics[
                                    f'E_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 0  # this creates it if not exists

                ## SECOND: T
                T = set(raw_result['cwe_llm_output']['TOP_FIVE_CWE_IDS'])
                self.cwe_equality_status['T'], metric_to_add_key = self.evaluate_cwe(T, 'T', GT_CWEs)

                metrics[metric_to_add_key] += 1
                if metric_to_add_key == 'T_IDENTICAL_CWE_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_T_EQUAL_LABEL_counter'] += 1
                    if self.severity_score_equality_status == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['EQUAL_T_EQUAL_SCORE_counter'] += 1
                    if self.severity_score_label_range_equality_status[
                        0] == SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL:
                        metrics['EQUAL_T_WITHIN_LABEL_RANGE_counter'] += 1

                    if self.severity_score_equality_radius_status[
                        0] == SeverityScoreAsRadius_EvaluationResultEnum.COVERS:
                        for r in sorted(constants.ANALYSIS_RADIUS):
                            metrics.setdefault(f'EQUAL_T_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
                            if self.severity_score_equality_radius_status[1] <= r:
                                metrics[f'EQUAL_T_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 1
                            else:
                                metrics[
                                    f'EQUAL_T_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 0  # this creates it if not exists


                elif metric_to_add_key == 'GT_SUBSET_OF_T_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['GT_SUBSET_OF_T_EQUAL_LABEL_counter'] += 1
                    if self.severity_score_equality_status == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['GT_SUBSET_OF_T_EQUAL_SCORE_counter'] += 1
                    if (self.severity_score_label_range_equality_status[
                        0] == SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL):
                        metrics['GT_SUBSET_OF_T_WITHIN_LABEL_RANGE_counter'] += 1

                    if self.severity_score_equality_radius_status[
                        0] == SeverityScoreAsRadius_EvaluationResultEnum.COVERS:
                        for r in sorted(constants.ANALYSIS_RADIUS):
                            metrics.setdefault(f'GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
                            if self.severity_score_equality_radius_status[1] <= r:
                                metrics[f'GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 1
                            else:
                                metrics[
                                    f'GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 0  # this creates it if not exists

                elif metric_to_add_key == 'T_SUBSET_OF_GT_counter':
                    if self.severity_label_equality_status == SeverityLabel_EvaluationResultEnum.IDENTICAL:
                        metrics['T_SUBSET_OF_GT_EQUAL_LABEL_counter'] += 1
                    if self.severity_score_equality_status == SeverityScore_EvaluationResultEnum.IDENTICAL_EXACT_MATCH:
                        metrics['T_SUBSET_OF_GT_EQUAL_SCORE_counter'] += 1
                    if self.severity_score_label_range_equality_status[
                        0] == SeverityScoreLabelRange_EvaluationResultEnum.IDENTICAL:
                        metrics['T_SUBSET_OF_GT_WITHIN_LABEL_RANGE_counter'] += 1

                    if self.severity_score_equality_radius_status[
                        0] == SeverityScoreAsRadius_EvaluationResultEnum.COVERS:
                        for r in sorted(constants.ANALYSIS_RADIUS):
                            metrics.setdefault(f'T_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
                            if self.severity_score_equality_radius_status[1] <= r:
                                metrics[f'T_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 1
                            else:
                                metrics[
                                    f'T_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}'] += 0  # this creates it if not exists

                self.valid_evaluation = True
            evaluations.append(self.toJson())

        to_return = {
            'TOTAL_NUMBER_OF_SAMPLES_counter': len(raw_experiment_result),
            'timestamp': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),

            'accuracy_overall_E_EQUAL_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_EQUAL_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_E_EQUAL_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_EQUAL_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_E_WITHIN_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_E_WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_T_EQUAL_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_EQUAL_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_EQUAL_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_EQUAL_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_WITHIN_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['EQUAL_T_WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_GT_SUBSET_OF_E_EQUAL_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['GT_SUBSET_OF_E_EQUAL_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_GT_SUBSET_OF_E_EQUAL_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['GT_SUBSET_OF_E_EQUAL_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_GT_SUBSET_OF_E_WITHIN_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['GT_SUBSET_OF_E_WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_GT_SUBSET_OF_T_EQUAL_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['GT_SUBSET_OF_T_EQUAL_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_GT_SUBSET_OF_T_EQUAL_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['GT_SUBSET_OF_T_EQUAL_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_GT_SUBSET_OF_T_WITHIN_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['GT_SUBSET_OF_T_WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_E_SUBSET_OF_GT_EQUAL_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['E_SUBSET_OF_GT_EQUAL_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_E_SUBSET_OF_GT_EQUAL_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['E_SUBSET_OF_GT_EQUAL_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_E_SUBSET_OF_GT_WITHIN_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['E_SUBSET_OF_GT_WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_overall_T_SUBSET_OF_GT_EQUAL_LABEL': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['T_SUBSET_OF_GT_EQUAL_LABEL_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_SUBSET_OF_GT_EQUAL_SCORE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['T_SUBSET_OF_GT_EQUAL_SCORE_counter'] / len(raw_experiment_result)),
            'accuracy_overall_T_SUBSET_OF_GT_WITHIN_LABEL_RANGE': 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['T_SUBSET_OF_GT_WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result)),

            'accuracy_identical_CWE_E': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'E_IDENTICAL_CWE_counter'] / len(raw_experiment_result),
            'accuracy_CWE_GT_SUBSET_OF_E': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'GT_SUBSET_OF_E_counter'] / len(raw_experiment_result),
            'accuracy_CWE_E_SUBSET_OF_GT': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'E_SUBSET_OF_GT_counter'] / len(raw_experiment_result),

            'accuracy_identical_CWE_T': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'T_IDENTICAL_CWE_counter'] / len(raw_experiment_result),
            'accuracy_CWE_GT_SUBSET_OF_T': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'GT_SUBSET_OF_T_counter'] / len(raw_experiment_result),
            'accuracy_CWE_T_SUBSET_OF_GT': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'T_SUBSET_OF_GT_counter'] / len(raw_experiment_result),

            'accuracy_empty_CWE_E': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'EMPTY_E_counter'] / len(raw_experiment_result),
            'accuracy_empty_CWE_T': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'EMPTY_T_counter'] / len(raw_experiment_result),
            'accuracy_non_overlapped_CWE_E': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'NON_OVERLAPPED_E_counter'] / len(raw_experiment_result),
            'accuracy_non_overlapped_CWE_T': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'NON_OVERLAPPED_T_counter'] / len(raw_experiment_result),
            'accuracy_overlapped_CWE_E': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'OVERLAPPED_E_counter'] / len(raw_experiment_result),
            'accuracy_overlapped_CWE_T': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'OVERLAPPED_T_counter'] / len(raw_experiment_result),

            'accuracy_identical_severity_label': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'EQUAL_LABEL_counter'] / len(raw_experiment_result),
            'accuracy_severity_score_exact_match': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'EQUAL_SCORE_counter'] / len(raw_experiment_result),
            'accuracy_severity_score_label_range': 0 if len(raw_experiment_result) == 0 else 100.0 * metrics[
                'WITHIN_LABEL_RANGE_counter'] / len(raw_experiment_result),
            'accuracy_severity_score_radius_range': 0 if len(raw_experiment_result) == 0 else 100.0 * list(
                metrics['WITHIN_RADIUS_RANGE_counter'].values())[-1] / len(raw_experiment_result),

            'SEVERITY_ERRORS': metrics['SEVERITY_ERROR_counter'],
            'CWE_ERRORS': metrics['CWE_ERROR_counter'],
            'INVALID_CWE_INFERENCE_counter': metrics['INVALID_CWE_INFERENCE_counter'],
            'INVALID_SEVERITY_INFERENCE_counter': metrics['INVALID_SEVERITY_INFERENCE_counter']
        }

        for r in sorted(constants.ANALYSIS_RADIUS):
            metrics.setdefault(f'EQUAL_E_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
            metrics.setdefault(f'EQUAL_T_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
            metrics.setdefault(f'GT_SUBSET_OF_E_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
            metrics.setdefault(f'GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
            metrics.setdefault(f'E_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
            metrics.setdefault(f'T_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}', 0)
            metrics.setdefault(f'accuracy_severity_score_radius_range_{str(r)}', 0)

            to_return[f'accuracy_severity_score_radius_range_{str(r)}'] = 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics['WITHIN_RADIUS_RANGE_counter'][r] / len(raw_experiment_result))

            to_return[f'accuracy_overall_E_WITHIN_RADIUS_RANGE_{str(r)}'] = 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics[f'EQUAL_E_WITHIN_RADIUS_RANGE_counter_{str(r)}'] / len(raw_experiment_result))

            to_return[f'accuracy_overall_T_WITHIN_RADIUS_RANGE_{str(r)}'] = 0 if len(raw_experiment_result) == 0 else (
                    100.0 * metrics[f'EQUAL_T_WITHIN_RADIUS_RANGE_counter_{str(r)}'] / len(raw_experiment_result))

            to_return[f'accuracy_overall_GT_SUBSET_OF_E_WITHIN_RADIUS_RANGE_{str(r)}'] = 0 if len(
                raw_experiment_result) == 0 else (
                    100.0 * metrics[f'GT_SUBSET_OF_E_WITHIN_RADIUS_RANGE_counter_{str(r)}'] / len(
                raw_experiment_result))

            to_return[f'accuracy_overall_GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_{str(r)}'] = 0 if len(
                raw_experiment_result) == 0 else (
                    100.0 * metrics[f'GT_SUBSET_OF_T_WITHIN_RADIUS_RANGE_counter_{str(r)}'] / len(
                raw_experiment_result))

            to_return[f'accuracy_overall_E_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_{str(r)}'] = 0 if len(
                raw_experiment_result) == 0 else (
                    100.0 * metrics[f'E_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}'] / len(
                raw_experiment_result))

            to_return[f'accuracy_overall_T_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_{str(r)}'] = 0 if len(
                raw_experiment_result) == 0 else (
                    100.0 * metrics[f'T_SUBSET_OF_GT_WITHIN_RADIUS_RANGE_counter_{str(r)}'] / len(
                raw_experiment_result))

        for r, r_freq in metrics['WITHIN_RADIUS_RANGE_counter'].items():
            to_return[f'accuracy_severity_score_radius_range_{str(r)}'] = 0 if len(
                raw_experiment_result) == 0 else 100.0 * r_freq / len(raw_experiment_result)

        to_return['metrics'] = metrics
        to_return['evaluations'] = evaluations

        return to_return

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
            'valid_evaluation': self.valid_evaluation,
            'ground_truth_severities': self.ground_truth_severities,
            'ground_truth_CWEs': self.ground_truth_CWEs,
            'severity_llm_output': self.severity_llm_output,
            'cwe_llm_output': self.cwe_llm_output,
            'cwe_equality_status': {k: (str(v) if isinstance(v, Enum) else v) for k, v in
                                    self.cwe_equality_status.items()},
            'severity_label_equality_status': None if self.severity_label_equality_status is None else str(
                self.severity_label_equality_status),
            'severity_score_equality_status': None if self.severity_score_equality_status is None else str(
                self.severity_score_equality_status),
            'severity_score_label_range_equality_status': {
                'type': None if self.severity_score_label_range_equality_status[0] is None else str(
                    self.severity_score_label_range_equality_status[0]),
                'label_range': self.severity_score_label_range_equality_status[1]},
            'severity_score_equality_radius_status': {
                'type': None if self.severity_score_equality_radius_status[0] is None else str(
                    self.severity_score_equality_radius_status[0]),
                'min_radius': self.severity_score_equality_radius_status[1]}
        }

    def reset_properties(self):
        self.reference_id = -1
        self.ground_truth_severities = -1
        self.ground_truth_CWEs = -1
        self.severity_llm_output = -1
        self.cwe_llm_output = -1
        self.cwe_equality_status = {'E': None, 'T': None}
        self.severity_label_equality_status = None
        self.severity_score_equality_status = None
        self.severity_score_label_range_equality_status = (None, None)
        self.severity_score_equality_radius_status = (None, None)
