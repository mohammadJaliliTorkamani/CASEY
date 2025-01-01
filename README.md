# Streamlining Security Vulnerability Triage with Large Language Models

## How to Run

1. Open `constants.py` and replace the placeholders (`OPENAI_API_KEY`, `PROJECT_ABSOLUTE_PATH`, `LLM_CWE_FINE_TUNED_MODEL`, `LLM_SEVERITY_FINE_TUNED_MODEL`) with the appropriate values.
2. To run the tool in experiment mode (for conducting experiments), set `EXPERIMENT_STAGE` to True.
3. To run it in evaluation mode (to analyze the JSON files generated during experiment mode), set `EXPERIMENT_STAGE` to False.
4. Other configuration options in constants.py can also be adjusted as needed.

Finally, run the project using the following command:

``python3 main.py``

## Links to Datasets:
You can have access to dataset artifacts using either of these two ways:
### Link-1:  
Including a link for all artifacts uploaded in Zenodo [Here](https://zenodo.org/records/14578172?token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6ImMzNmQwMzc4LTg5NzctNGI2OS04NGRjLWIzODIxNWM4NTdjMSIsImRhdGEiOnt9LCJyYW5kb20iOiJiMjdjNzExOGFiNjE5YzU4YTUyZTI1MWQxNGEzMDc5MSJ9.BTmonq6aT7lA_jut33V6VY8ZsZ-MOEGUtDg8uHQuisJhMRzwk4nnotL3yyDjTCJz6YZg631LKyoAAdF8lYSykQ)

### Link-2: 
Direct links for each one of the artifacts:
### Total Dataset: [https://mega.nz/file/s7tH2DKQ#343OYhB9fb8F_9rY6N-q-0twhhLbZRnVlQLLnBtLZ1o]
### CVE2CWE Dataset: [https://mega.nz/file/Bj9VWR7a#DuSu6kDmIFtD4xiZDzsQXpjNOfF-7uYIbn_6k1-Vct0]
### Evaluation Dataset: [https://mega.nz/file/YvUzAbBR#3rpznGlsiLSYa1WDvxeTk3ObzMaLDQXzYxgoSzwu56k]
### Fine-tuning Dataset (CWE+Severity): [https://mega.nz/file/cjFEQaKT#w5ZPAVEDRPgSj47hodZS5rwWHqmmjcSTL7sIFxULQjU]
### Fine-tuning Dataset (CWE - Training): [https://mega.nz/file/16kkFCIT#A4zDTHK-mM34KKf4wJUnthQeHRXnD41J5Br1Xogojcw]
### Fine-tuning Dataset (CWE - Testing): [https://mega.nz/file/YrlyiKaA#oprGrrJqrWOiZmCKxPdMyLSBFfVpgxa1s1eCU5zlxzE]
### Fine-tuning Dataset (Severity - Training): [https://mega.nz/file/d2UkwIIZ#PvoilsWpVwIkxsD5q4mHS-GV1TkvnbbpBcSAvfltk0A]
### Fine-tuning Dataset (Severity - Testing): [https://mega.nz/file/dy1DUDjC#flcYEorpKZrt3FrTNLGjEJqNWm522rVRoyOFkvgmhWc]

Preprint paper:
https://