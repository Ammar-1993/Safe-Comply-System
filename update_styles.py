import os
import re

files_to_update = [
    'app/templates/settings.html',
    'app/templates/reports.html',
    'app/templates/policies.html',
    'app/templates/recommendations.html',
    'app/templates/compliance-report-view.html',
    'app/templates/backup-policies.html',
    'app/templates/password-policies.html'
]

new_links = """  <link rel="stylesheet" href="{{ url_for('static', filename='css/variables.css') }}" />
  <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}" />
  <link rel="stylesheet" href="{{ url_for('static', filename='css/modal.css') }}" />"""

base_dir = os.getcwd()

for relative_path in files_to_update:
    file_path = os.path.join(base_dir, relative_path)
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        continue

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Regex to match the first <style>...</style> block
    # We use non-greedy match .*? and flags=re.DOTALL to match across lines
    pattern = re.compile(r'<style>.*?</style>', re.DOTALL)
    
    # Check if it looks like the main style block (contains "body {")
    match = pattern.search(content)
    if match:
        matched_content = match.group(0)
        if "body {" in matched_content or "* {" in matched_content:
            new_content = pattern.sub(new_links, content, count=1)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Updated {relative_path}")
        else:
            print(f"Skipped {relative_path}: First style block doesn't look like the main one.")
    else:
        print(f"No style block found in {relative_path}")
