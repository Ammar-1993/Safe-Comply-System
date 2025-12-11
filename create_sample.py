import pandas as pd
import random

# Generate sample data
data = []
for i in range(1, 21):
    data.append({
        'username': f'user{i}',
        'password': 'Password123' if i % 3 == 0 else 'secureP@ssw0rd!', # Some weak
        'last_backup': '2024-12-01' if i % 2 == 0 else '2024-11-01', # Some old
        'backup_frequency': 'daily' if i % 4 != 0 else 'never',
        'backup_type': 'full'
    })

df = pd.DataFrame(data)
df.to_excel('sample_compliance.xlsx', index=False)
print("Created sample_compliance.xlsx")
