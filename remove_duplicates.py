import os

files_to_check = [
    'app/templates/settings.html',
    'app/templates/reports.html',
    'app/templates/policies.html',
    'app/templates/recommendations.html',
    'app/templates/compliance-report-view.html',
    'app/templates/backup-policies.html',
    'app/templates/password-policies.html'
]

duplicate_line = '  <link rel="stylesheet" href="{{ url_for(\'static\', filename=\'css/modal.css\') }}" />'

base_dir = os.getcwd()

for relative_path in files_to_check:
    file_path = os.path.join(base_dir, relative_path)
    if not os.path.exists(file_path):
        continue

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    new_lines = []
    found_modal = False
    
    for line in lines:
        stripped = line.strip()
        if 'css/modal.css' in stripped:
            if not found_modal:
                new_lines.append(line)
                found_modal = True
            # else skip duplicate
        else:
            new_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print(f"Cleaned {relative_path}")
