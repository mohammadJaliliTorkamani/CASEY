import os
import random

import constants
import utils

data_array = utils.load_json_file(constants.DATA_PATH)
random.shuffle(data_array)

fine_tuning_dataset = data_array[:int(len(data_array) * constants.DATASET_SPLIT_RATIO)]
evaluation_dataset = data_array[int(len(data_array) * constants.DATASET_SPLIT_RATIO):]

utils.save_json(constants.EVALUATION_DATASET_PATH, evaluation_dataset)
utils.save_json(constants.FINE_TUNING_JSON_DATASET_PATH, fine_tuning_dataset)


data_array1 = utils.load_json_file(constants.EVALUATION_DATASET_PATH)
data_array2 = utils.load_json_file(constants.FINE_TUNING_JSON_DATASET_PATH)

print(len(data_array1), len(data_array2))