import os
from app import create_app

config_name = os.getenv('FLASK_CONFIG') or 'default'
app = create_app(config_name)

if __name__ == '__main__':
    port = app.config.get('PORT', 5002)
    app.run(host='0.0.0.0', port=port)
