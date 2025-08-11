import os
from flask import Flask
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
import openai
from config import config
from models import db
from datetime import datetime, timezone
import requests
from requests.auth import HTTPBasicAuth
from models import Blog, Settings, db
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from flask_cors import CORS
import mimetypes

# Initialize login manager
login_manager = LoginManager()
login_manager.login_view = "admin_login"


def post_to_wordpress(blog, settings):
    wp_url = settings.get("wp_site_url", "").rstrip("/")
    wp_user = settings.get("wp_username", "")
    wp_app_password = settings.get("wp_app_password", "")
    if not (wp_url and wp_user and wp_app_password):
        log_error(
            "WordPress credentials missing or incomplete. Blog ID: {}".format(blog.id)
        )
        return False, "WordPress credentials not set."
    api_url = f"{wp_url}/wp-json/wp/v2/posts"
    data = {
        "title": blog.title,
        "content": blog.content,
        "status": "publish" if blog.status == "published" else "draft",
    }
    if blog.scheduled_at:
        data["date"] = blog.scheduled_at.isoformat()
    try:
        response = requests.post(
            api_url, json=data, auth=HTTPBasicAuth(wp_user, wp_app_password), timeout=10
        )
        if response.status_code in (200, 201):
            post_id = response.json().get("id")
            blog.posted_to_wordpress = True
            blog.wordpress_post_id = str(post_id)
            blog.wp_error = None
            db.session.commit()
            return True, None
        else:
            blog.wp_error = response.text
            db.session.commit()
            log_error(f"WordPress post failed for Blog ID {blog.id}: {response.text}")
            return False, response.text
    except Exception as e:
        blog.wp_error = str(e)
        db.session.commit()
        log_error(f"Exception posting to WordPress for Blog ID {blog.id}: {str(e)}")
        return False, str(e)




def post_to_twitter(blog, settings):
    """Post to Twitter/X"""
    try:
        api_key = settings.get("x_api_key")
        api_secret = settings.get("x_api_secret")
        access_token = settings.get("x_access_token")
        access_token_secret = settings.get("x_access_token_secret")

        if not all([api_key, api_secret, access_token, access_token_secret]):
            log_error(f"Twitter credentials missing for Blog ID: {blog.id}")
            return False, "Twitter credentials not set."

        try:
            import tweepy

            # Authenticate with Twitter
            auth = tweepy.OAuthHandler(api_key, api_secret)
            auth.set_access_token(access_token, access_token_secret)
            api = tweepy.API(auth)

            # Post the tweet with image if available
            if blog.image_path:
                try:
                    # Upload image first
                    media = api.media_upload(blog.image_path)
                    # Post tweet with image
                    tweet = api.update_status(blog.content, media_ids=[media.media_id])
                except Exception as e:
                    log_error(
                        f"Failed to upload image to Twitter for Blog ID {blog.id}: {str(e)}"
                    )
                    # Post tweet without image
                    tweet = api.update_status(blog.content)
            else:
                # Post tweet without image
                tweet = api.update_status(blog.content)

            blog.posted_to_x = True
            blog.x_post_id = str(tweet.id)
            blog.x_error = None
            db.session.commit()
            return True, None

        except ImportError:
            log_error(
                "Tweepy library not installed. Please install it with: pip install tweepy"
            )
            return False, "Tweepy library not installed"

    except Exception as e:
        blog.x_error = str(e)
        db.session.commit()
        log_error(f"Exception posting to Twitter for Blog ID {blog.id}: {str(e)}")
        return False, str(e)


def send_scheduled_post_notification(blog, settings, success=True, error=None):
    """Send email notification about scheduled post status"""
    try:
        # Get notification email from settings
        notification_email = settings.get("log_sending_email")
        if not notification_email:
            return  # No email configured for notifications

        # Get SMTP settings
        smtp_server = settings.get("SMTP_SERVER")
        smtp_port = settings.get("SMTP_PORT")
        sender_email = settings.get("SMTP_USERNAME")
        password = settings.get("SMTP_PASSWORD")

        if not all([smtp_server, smtp_port, sender_email, password]):
            log_error(f"SMTP settings incomplete for scheduled post notification")
            return

        # Prepare email content
        if success:
            subject = f"✅ Scheduled Post Published: {blog.title}"
            body = f"""
            <h3>Scheduled Post Successfully Published</h3>
            <p><strong>Title:</strong> {blog.title}</p>
            <p><strong>Blog ID:</strong> {blog.id}</p>
            <p><strong>Scheduled Time:</strong> {blog.scheduled_at.strftime('%Y-%m-%d %H:%M:%S') if blog.scheduled_at else 'N/A'}</p>
            <p><strong>Published Time:</strong> {datetime.now().replace(tzinfo=None).isoformat()}</p>
            <p><strong>WordPress Post ID:</strong> {blog.wordpress_post_id or 'N/A'}</p>
            <p><strong>Status:</strong> {blog.status}</p>
            """
        else:
            subject = f"❌ Scheduled Post Failed: {blog.title}"
            body = f"""
            <h3>Scheduled Post Failed to Publish</h3>
            <p><strong>Title:</strong> {blog.title}</p>
            <p><strong>Blog ID:</strong> {blog.id}</p>
            <p><strong>Scheduled Time:</strong> {blog.scheduled_at.strftime('%Y-%m-%d %H:%M:%S') if blog.scheduled_at else 'N/A'}</p>
            <p><strong>Error Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Error:</strong> {error or 'Unknown error'}</p>
            <p><strong>Status:</strong> {blog.status}</p>
            """

        # Send email
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = notification_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP_SSL(smtp_server, int(smtp_port)) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, notification_email, msg.as_string())

        # log_error(f'Scheduled post notification email sent to {notification_email}')

    except Exception as e:
        log_error(f"Failed to send scheduled post notification email: {str(e)}")


def log_error(message):
    try:
        with create_app().app_context():
            # Append to log in Settings
            log_setting = db.session.query(Settings).filter_by(key="log").first()
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{now}] {message}\n"
            if log_setting:
                log_setting.value = (log_setting.value or "") + log_entry
            else:
                log_setting = Settings(key="log", value=log_entry)
                db.session.add(log_setting)
            db.session.commit()
            # Send email if log_sending_email is set
            log_email_setting = (
                db.session.query(Settings).filter_by(key="log_sending_email").first()
            )
            if log_email_setting and log_email_setting.value:
                try:
                    smtp_server = (
                        db.session.query(Settings)
                        .filter_by(key="SMTP_SERVER")
                        .first()
                        .value
                    )
                    port = int(
                        db.session.query(Settings)
                        .filter_by(key="SMTP_PORT")
                        .first()
                        .value
                    )
                    sender_email = (
                        db.session.query(Settings)
                        .filter_by(key="SMTP_USERNAME")
                        .first()
                        .value
                    )
                    password = (
                        db.session.query(Settings)
                        .filter_by(key="SMTP_PASSWORD")
                        .first()
                        .value
                    )
                    receiver_email = log_email_setting.value
                    subject = "Agentic Marketer Error Log"
                    body = message
                    msg = MIMEMultipart()
                    msg["From"] = sender_email
                    msg["To"] = receiver_email
                    msg["Subject"] = subject
                    msg.attach(MIMEText(body, "plain"))
                    with smtplib.SMTP_SSL(smtp_server, port) as server:
                        server.login(sender_email, password)
                        server.sendmail(sender_email, receiver_email, msg.as_string())
                except Exception as e:
                    # If email fails, append to log
                    fail_entry = f"[{now}] Failed to send log email: {str(e)}\n"
                    log_setting.value += fail_entry
                    db.session.commit()
    except Exception as e:
        # Fallback to console logging
        print(f"Log error failed: {str(e)}")
        print(f"Original message: {message}")


def create_app(config_name="default"):
    """Create and configure the Flask application."""
    global scheduler

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
        return db.session.get(User, int(user_id))

    # Context processor for settings
    @app.context_processor
    def inject_settings():
        settings = {s.key: s.value for s in Settings.query.all()}
        return dict(settings=settings)

    # Update OpenAI API key when settings change
    @app.before_request
    def update_openai_key():
        if current_user.is_authenticated:
            openai.api_key = (
                db.session.query(Settings).filter_by(key="openai_key").first().value
            )

    # Import and register blueprints
    from routes import main as main_blueprint

    app.register_blueprint(main_blueprint)

    # Initialize recurring newsletter jobs after app is created
    # with app.app_context():
    #     init_recurring_newsletter_jobs()

    return app


if __name__ == "__main__":
    app = create_app()
    CORS(app)
    # app.run(host="0.0.0.0", port=5678, debug=True,use_reloader=False)
    app.run( port=5678, debug=True)
