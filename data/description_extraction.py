import re

import requests
from bs4 import BeautifulSoup


def get_commit_message(url_commit):
    response = requests.get(url_commit)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        commit_message_tag = soup.find('div', class_='commit-title')
        if commit_message_tag:
            commit_message = commit_message_tag.text.strip()
            return commit_message
        else:
            print("Commit message not found. HTML structure may have changed.")
            print(soup.prettify())  # Print HTML for debugging
            return None
    else:
        print(f"Failed to retrieve commit message. Status code: {response.status_code}")
        return None


def extract_pull_request_links(commit_message):
    pr_links = re.findall(r'#\d+', commit_message)
    return pr_links


def get_pull_request_description(repo_url, pr_numbers):
    pr_url = f"{repo_url}/pull/{pr_numbers}"
    response = requests.get(pr_url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        pr_description_tag = soup.find('div', class_='edit-comment-hide')
        if pr_description_tag:
            pr_description = pr_description_tag.text.strip()
            return pr_description
        else:
            print(f"No description found for pull request #{pr_numbers}.")
            return None
    else:
        print(f"Failed to retrieve pull request description for #{pr_numbers}. Status code: {response.status_code}")
        return None


def extract_issue_description_from_commit(commit_urls):
    repo_url = '/'.join(commit_urls.split('/')[:5])
    commit_message = get_commit_message(commit_urls)
    if commit_message:
        print(f"Commit message: {commit_message}")
        pr_links = extract_pull_request_links(commit_message)
        pr_descriptions = {}
        if pr_links:
            for pr_link in pr_links:
                pr_numbers = pr_link[1:]  # Remove the hashtag
                print(f"Fetching description for pull request #{pr_numbers}")
                pr_description = get_pull_request_description(repo_url, pr_numbers)
                if pr_description:
                    pr_descriptions[pr_numbers] = pr_description
        else:
            print("No pull request links found in the commit message.")
            return None
        if pr_descriptions:
            return pr_descriptions
        else:
            return None
    else:
        print("Could not fetch the commit message.")
        return None


# Ensure the main block is not required for import
if __name__ == "__main__":
    commit_url = input("Enter the GitHub commit URL: ")
    descriptions = extract_issue_description_from_commit(commit_url)
    if descriptions:
        for pr_number, description in descriptions.items():
            print(f"Pull Request #{pr_number} Description: {description}")
    else:
        print("No descriptions found.")
