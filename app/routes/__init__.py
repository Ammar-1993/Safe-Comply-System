def register_routes(app):
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.reports import reports_bp
    from app.routes.api import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp)
