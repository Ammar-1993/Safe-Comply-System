import pandas as pd
from datetime import datetime, timedelta

# Generate sample data with current dates
data = []
today = datetime.now()
for i in range(1, 21):
    # Some users have recent backups (within 7 days), others have old ones
    if i % 2 == 0:
        # Recent backup - within last 3 days
        backup_date = (today - timedelta(days=i % 5)).strftime('%Y-%m-%d')
    else:
        # Old backup - more than 7 days ago
        backup_date = (today - timedelta(days=10 + i)).strftime('%Y-%m-%d')
    
    data.append({
        'username': f'user{i}',
        'password': 'Password123' if i % 3 == 0 else 'secureP@ssw0rd!', # Some weak
        'last_backup': backup_date,
        'backup_frequency': 'daily' if i % 4 != 0 else 'never',
        'backup_type': 'full',
        'retention_days': 30 if i % 5 != 0 else 15  # Some users don't meet retention requirement
    })

df = pd.DataFrame(data)
df.to_excel('sample_compliance.xlsx', index=False)
print("Created sample_compliance.xlsx with updated dates")
