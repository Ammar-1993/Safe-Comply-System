from flask import Flask
from config import config
from app.extensions import db, cors
from flask_migrate import Migrate

migrate = Migrate()

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Configure CORS
    cors_origins = app.config.get('CORS_ORIGINS', '*')
    if cors_origins == '*' or cors_origins.strip() == '':
        cors.init_app(app)
    else:
        cors.init_app(app, origins=[o.strip() for o in cors_origins.split(',')])

    # Register Blueprints
    from app.routes import register_routes
    register_routes(app)

    return app
