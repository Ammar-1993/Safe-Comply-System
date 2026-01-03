import os

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SAFE_COMPLY_SECRET') or 'dev-secret-key'
    DEBUG = os.environ.get('SAFE_COMPLY_DEBUG', 'true').lower() in ('1', 'true', 'yes')
    PORT = int(os.environ.get('SAFE_COMPLY_PORT', '5002'))
    CORS_ORIGINS = os.environ.get('SAFE_COMPLY_CORS', '*')
    # Bump this (or set env SAFE_COMPLY_STATIC_VERSION) to force browsers to reload static assets.
    STATIC_VERSION = os.environ.get('SAFE_COMPLY_STATIC_VERSION', '1')
    
    # Database
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DB_NAME = 'safecomply.db'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f"sqlite:///{os.path.join(BASE_DIR, DB_NAME)}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        if not os.environ.get('SAFE_COMPLY_SECRET'):
             raise ValueError("SAFE_COMPLY_SECRET environment variable is required in production")

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
