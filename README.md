# BugSight: Predictive Analysis of CWE and Bug Severity Using Large Language Models

## How to Run

1. Open `constants.py` and replace the placeholders (`OPENAI_API_KEY`, `PROJECT_ABSOLUTE_PATH`, `LLM_CWE_FINE_TUNED_MODEL`, `LLM_SEVERITY_FINE_TUNED_MODEL`) with the appropriate values.
2. To run the tool in experiment mode (for conducting experiments), set `EXPERIMENT_STAGE` to True.
3. To run it in evaluation mode (to analyze the JSON files generated during experiment mode), set `EXPERIMENT_STAGE` to False.
4. Other configuration options in constants.py can also be adjusted as needed.

Finally, run the project using the following command:

``python3 main.py``

Preprint paper:
https://