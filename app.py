import os
from flask import Flask
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
import openai
from config import config
from models import db
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
from models import Blog, Settings, db
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

# Initialize login manager
login_manager = LoginManager()
login_manager.login_view = 'admin_login'

def post_to_wordpress(blog, settings):
    wp_url = settings.get('wp_site_url', '').rstrip('/')
    wp_user = settings.get('wp_username', '')
    wp_app_password = settings.get('wp_app_password', '')
    if not (wp_url and wp_user and wp_app_password):
        log_error('WordPress credentials missing or incomplete. Blog ID: {}'.format(blog.id))
        return False, 'WordPress credentials not set.'
    api_url = f"{wp_url}/wp-json/wp/v2/posts"
    data = {
        "title": blog.title,
        "content": blog.content,
        "status": "publish" if blog.status == "published" else "future",
    }
    if blog.scheduled_at:
        data["date"] = blog.scheduled_at.isoformat()
    try:
        response = requests.post(
            api_url,
            json=data,
            auth=HTTPBasicAuth(wp_user, wp_app_password),
            timeout=10
        )
        if response.status_code in (200, 201):
            post_id = response.json().get('id')
            blog.posted_to_wordpress = True
            blog.wordpress_post_id = str(post_id)
            blog.wp_error = None
            db.session.commit()
            return True, None
        else:
            blog.wp_error = response.text
            db.session.commit()
            log_error(f'WordPress post failed for Blog ID {blog.id}: {response.text}')
            return False, response.text
    except Exception as e:
        blog.wp_error = str(e)
        db.session.commit()
        log_error(f'Exception posting to WordPress for Blog ID {blog.id}: {str(e)}')
        return False, str(e)

def publish_scheduled_blogs():
    with create_app().app_context():
        now = datetime.utcnow()
        settings = {s.key: s.value for s in Settings.query.all()}
        blogs = Blog.query.filter(
            Blog.status == 'scheduled',
            Blog.scheduled_at <= now,
            Blog.post_to_wordpress == True,
            Blog.posted_to_wordpress == False
        ).all()
        for blog in blogs:
            blog.status = 'published'
            db.session.commit()
            try:
                post_to_wordpress(blog, settings)
            except Exception as e:
                log_error(f'Exception in scheduled WordPress publish for Blog ID {blog.id}: {str(e)}')

scheduler = BackgroundScheduler()
scheduler.add_job(publish_scheduled_blogs, 'interval', minutes=1)
scheduler.start()

def log_error(message):
    from flask import current_app
    with create_app().app_context():
        # Append to log in Settings
        log_setting = Settings.query.filter_by(key='log').first()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{now}] {message}\n"
        if log_setting:
            log_setting.value = (log_setting.value or '') + log_entry
        else:
            log_setting = Settings(key='log', value=log_entry)
            db.session.add(log_setting)
        db.session.commit()
        # Send email if log_sending_email is set
        log_email_setting = Settings.query.filter_by(key='log_sending_email').first()
        if log_email_setting and log_email_setting.value:
            try:
                smtp_server = Settings.query.filter_by(key='SMTP_SERVER').first().value
                port = int(Settings.query.filter_by(key='SMTP_PORT').first().value)
                sender_email = Settings.query.filter_by(key='SMTP_USERNAME').first().value
                password = Settings.query.filter_by(key='SMTP_PASSWORD').first().value
                receiver_email = log_email_setting.value
                subject = "Agentic Marketer Error Log"
                body = message
                msg = MIMEMultipart()
                msg['From'] = sender_email
                msg['To'] = receiver_email
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'plain'))
                with smtplib.SMTP_SSL(smtp_server, port) as server:
                    server.login(sender_email, password)
                    server.sendmail(sender_email, receiver_email, msg.as_string())
            except Exception as e:
                # If email fails, append to log
                fail_entry = f"[{now}] Failed to send log email: {str(e)}\n"
                log_setting.value += fail_entry
                db.session.commit()

def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    migrate = Migrate(app, db)  # Initialize Flask-Migrate
    login_manager.init_app(app)
    
    # Import models after db initialization
    from models import User, Role, FAQ, Settings, Blog, LinkedInPost, TwitterPost
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Context processor for settings
    @app.context_processor
    def inject_settings():
        settings = {s.key: s.value for s in Settings.query.all()}
        return dict(settings=settings)
    
    # Update OpenAI API key when settings change
    @app.before_request
    def update_openai_key():
        if current_user.is_authenticated:
            openai.api_key = Settings.query.filter_by(key='openai_key').first().value
    
    # Import and register blueprints
    from routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    return app

if __name__ == '__main__':
    app = create_app('development')
    app.run(host='0.0.0.0', port=8080) 