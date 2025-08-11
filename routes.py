from curses import raw
from zoneinfo import ZoneInfo
import curses
from types import SimpleNamespace
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    session,
    current_app,
    abort,
)
from sqlalchemy.exc import SQLAlchemyError
import feedparser

import re
from sqlalchemy import func
from flask_login import login_user, login_required, logout_user, current_user
from models import (
    db,
    User,
    Role,
    FAQ,
    Settings,
    Blog,
    LinkedInPost,
    TwitterPost,
    NewsletterEmail,
    Newsletter,
    RssUrl,
)
from urllib.parse import urlparse, urljoin, urlunparse

from werkzeug.security import generate_password_hash
from datetime import datetime, timezone
import os
from embed_and_search import (
    generate_and_store_embeddings,
    search_across_indices,
    split_into_chunks,
    create_embedding,
)
from openai import OpenAI
import json
import numpy as np
import uuid
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.formatters import TextFormatter
from pathlib import Path
from werkzeug.utils import secure_filename
import smtplib
from email.mime.multipart import MIMEMultipart
import mimetypes
from email.mime.text import MIMEText
from app import post_to_wordpress, log_error
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
import calendar
import html


# Create blueprint
main = Blueprint("main", __name__)

# Public routes
@main.route("/")
def index():
    # redirect to /admin/login
    return redirect(url_for("main.admin_login"))
    # faqs = FAQ.query.all()
    # settings = {s.key: s.value for s in Settings.query.all()}
    # return render_template("public/index.html", faqs=faqs, settings=settings)


@main.route("/about")
def about():
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("public/about.html", settings=settings)


@main.route("/contact")
def contact():
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("public/contact.html", settings=settings)


def utc_naive_to_local(dt):
    if dt:
        return dt.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Europe/Helsinki"))
    return None


@main.route("/api/chat", methods=["POST"])
def chat():
    data = request.json
    question = data.get("question")
    language = data.get("language", "en")  # default to English

    if not question:
        return jsonify({"error": "No question provided", "type": "error"}), 400

    try:

        # 1. Check if exact match exists in FAQ
        faq = FAQ.query.filter(func.lower(FAQ.question) == question.lower()).first()
        if faq:

            return jsonify(
                {
                    "answer": faq.answer,
                    "type": "success",
                    "query_id": faq.id,
                    "faq_id": faq.id,
                }
            )

        # 2. Ensure OpenAI key is set
        openai_key = Settings.query.filter_by(key="openai_key").first()
        if not openai_key or not openai_key.value:
            return (
                jsonify(
                    {
                        "answer": "This project is not configured properly. Please contact the responsible person.",
                        "type": "error",
                    }
                ),
                400,
            )

            # 5. Generate answer via OpenAI
        system_prompt = {
            "en": "You are a helpful assistant. Use the following context to answer the question in English. If the context doesn't contain enough information to answer the question, say so:",
            "fi": "Olet avulias assistentti. Käytä seuraavaa kontekstia vastataksesi kysymykseen suomeksi. Jos kontekstissa ei ole tarpeeksi tietoa vastataksesi kysymykseen, kerro niin:",
        }
        context = ""
        client = OpenAI(api_key=openai_key.value)
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt.get(language, system_prompt["en"]),
                },
                {
                    "role": "user",
                    "content": f"Context: {context}\n\nQuestion: {question}",
                },
            ],
            temperature=0.8,
            max_tokens=500,
        )

        answer = response.choices[0].message.content

        return jsonify({"answer": answer, "type": "success"})

    except Exception as e:
        print(f"Error in chat route: {str(e)}")
        return jsonify({"error": str(e), "type": "error"}), 500


# Admin routes
@main.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("main.admin_dashboard"))
        flash("Invalid email or password", "error")
    return render_template("admin/login.html")


@main.route("/admin/logout")
@login_required
def admin_logout():
    logout_user()
    flash("You have been logged out successfully", "success")
    return redirect(url_for("main.admin_login"))


@main.route("/admin")
@login_required
def admin_dashboard():
    current_time = datetime.now()
    users = User.query.all()
    faqs = FAQ.query.all()
    newsletters = Newsletter.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template(
        "admin/dashboard.html",
        users=users,
        faqs=faqs,
        newsletters=newsletters,
        settings=settings,
        current_time=current_time,
    )


# CRUD routes for admin
@main.route("/admin/profile", methods=["GET", "POST"])
@login_required
def admin_profile():
    if request.method == "POST":
        try:
            current_user.name = request.form.get("name")
            current_user.phone = request.form.get("phone")
            if request.form.get("password"):
                current_user.set_password(request.form.get("password"))
            db.session.commit()
            flash("Profile updated successfully", "success")
        except Exception as e:
            flash(f"Error updating profile: {str(e)}", "error")
    return render_template("admin/profile.html")


@main.route("/admin/users")
@login_required
def admin_users():
    users = User.query.all()
    roles = Role.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template(
        "admin/users.html", users=users, roles=roles, settings=settings
    )


@main.route("/admin/faqs")
@login_required
def admin_faqs():
    faqs = FAQ.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/faqs.html", faqs=faqs, settings=settings)


@main.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    if request.method == "POST":
        try:
            # Handle file uploads
            upload_dir = os.path.join(current_app.static_folder, "uploads")
            os.makedirs(upload_dir, exist_ok=True)

            settings_to_update = {
                "logo": request.form.get("logo"),
                "openai_key": request.form.get("openai_key"),
                "copyright": request.form.get("copyright"),
                "about": request.form.get("about"),
                "contact": request.form.get("contact"),
                "log_sending_email": request.form.get("log_sending_email"),
                "email_starting": request.form.get("email_starting"),
                "email_ending": request.form.get("email_ending"),
            }

            # Handle logo file upload
            logo_file = request.files.get("logo_file")
            if logo_file and logo_file.filename:
                # Delete old logo if exists
                old_logo = Settings.query.filter_by(key="logo_file").first()
                if old_logo and old_logo.value:
                    old_logo_path = os.path.join(upload_dir, old_logo.value)
                    if os.path.exists(old_logo_path):
                        os.remove(old_logo_path)

                # Save new logo
                filename = secure_filename(logo_file.filename)
                logo_file.save(os.path.join(upload_dir, filename))
                settings_to_update["logo_file"] = filename

            # Handle favicon file upload
            favicon_file = request.files.get("favicon_file")
            if favicon_file and favicon_file.filename:
                # Delete old favicon if exists
                old_favicon = Settings.query.filter_by(key="favicon_file").first()
                if old_favicon and old_favicon.value:
                    old_favicon_path = os.path.join(upload_dir, old_favicon.value)
                    if os.path.exists(old_favicon_path):
                        os.remove(old_favicon_path)

                # Save new favicon
                filename = secure_filename(favicon_file.filename)
                favicon_file.save(os.path.join(upload_dir, filename))
                settings_to_update["favicon_file"] = filename

            for key, value in settings_to_update.items():
                setting = Settings.query.filter_by(key=key).first()
                if setting:
                    setting.value = value
                else:
                    setting = Settings(key=key, value=value)
                    db.session.add(setting)

            db.session.commit()
            return jsonify(
                {"message": "Settings updated successfully", "type": "success"}
            )
        except Exception as e:
            return (
                jsonify(
                    {"message": f"Error updating settings: {str(e)}", "type": "error"}
                ),
                500,
            )

    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/settings.html", settings=settings)


@main.route("/admin/platform-settings", methods=["GET", "POST"])
@login_required
def platform_settings():
    if request.method == "POST":
        try:

            settings_to_update = {
                "SMTP_SERVER": request.form.get("SMTP_SERVER"),
                "SMTP_PORT": request.form.get("SMTP_PORT"),
                "SMTP_USERNAME": request.form.get("SMTP_USERNAME"),
                "SMTP_PASSWORD": request.form.get("SMTP_PASSWORD"),
                # --- WordPress ---
                "wp_site_url": request.form.get("wp_site_url"),
                "wp_username": request.form.get("wp_username"),
                "wp_app_password": request.form.get("wp_app_password"),
                # --- LinkedIn ---
                "linkedin_client_id": request.form.get("linkedin_client_id"),
                "linkedin_client_secret": request.form.get("linkedin_client_secret"),
                "linkedin_redirect_uri": request.form.get("linkedin_redirect_uri"),
                "linkedin_org_id": request.form.get("linkedin_org_id"),
                "linkedin_auth_code": request.form.get("linkedin_auth_code"),
                "linkedin_access_token": request.form.get("linkedin_access_token"),
                "linkedin_refresh_token": request.form.get("linkedin_refresh_token"),
                # --- X (Twitter) ---
                "x_api_key": request.form.get("x_api_key"),
                "x_api_secret": request.form.get("x_api_secret"),
                "x_access_token": request.form.get("x_access_token"),
                "x_access_token_secret": request.form.get("x_access_token_secret"),
            }

            for key, value in settings_to_update.items():
                setting = Settings.query.filter_by(key=key).first()
                if setting:
                    setting.value = value
                else:
                    setting = Settings(key=key, value=value)
                    db.session.add(setting)

            db.session.commit()
            return jsonify(
                {"message": "Settings updated successfully", "type": "success"}
            )
        except Exception as e:
            return (
                jsonify(
                    {"message": f"Error updating settings: {str(e)}", "type": "error"}
                ),
                500,
            )

    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/platform-setting.html", settings=settings)


@main.route("/admin/newsletter-emails")
@login_required
def admin_newsletter():
    emails = NewsletterEmail.query.order_by(NewsletterEmail.created_at.desc()).all()
    newsletters = Newsletter.query.order_by(Newsletter.created_at.desc()).all()
    for newsletter in newsletters:
        newsletter.local_scheduled_at = utc_naive_to_local(newsletter.scheduled_at)

    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template(
        "admin/newsletter.html",
        emails=emails,
        newsletters=newsletters,
        settings=settings,
    )


@main.route("/admin/subscription")
@login_required
def admin_subscription():
    emails = NewsletterEmail.query.order_by(NewsletterEmail.created_at.desc()).all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/subscription.html", emails=emails, settings=settings)


@main.route("/admin/subscription/add", methods=["POST"])
@login_required
def add_subscription_email():
    email = request.form.get("email")
    if email:
        existing = NewsletterEmail.query.filter_by(email=email).first()
        if existing:
            flash("Email already exists.", "warning")
        else:
            new_email = NewsletterEmail(email=email)
            db.session.add(new_email)
            db.session.commit()
            flash("Email added successfully.", "success")
    return redirect(url_for("main.admin_subscription"))


@main.route("/admin/subscription/toggle/<int:email_id>", methods=["POST"])
@login_required
def toggle_subscription_email(email_id):
    email_entry = db.session.get(NewsletterEmail, email_id)
    if not email_entry:
        abort(404)
    email_entry.is_active = not email_entry.is_active
    db.session.commit()
    flash("Email status updated successfully.", "success")
    return redirect(url_for("main.admin_subscription"))


@main.route("/admin/subscription/delete/<int:email_id>", methods=["POST"])
@login_required
def delete_subscription_email(email_id):
    email_entry = db.session.get(NewsletterEmail, email_id)
    if not email_entry:
        abort(404)
    db.session.delete(email_entry)
    db.session.commit()
    flash("Email deleted successfully.", "success")
    return redirect(url_for("main.admin_subscription"))


@main.route("/admin/custom-newsletter")
@login_required
def custom_newsletter():
    """Custom newsletter creation page"""
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/custom_newsletter.html", settings=settings)


@main.route("/admin/custom-newsletter/create", methods=["POST"])
@login_required
def create_custom_newsletter():
    """Create a new custom newsletter"""
    # DEBUG (you can keep while testing)
    raw_selected = request.form.get("selected_posts") or ""
    print("RAW selected_posts INCOMING:", raw_selected[:200], flush=True)
    print("RAW TYPE:", type(raw_selected), flush=True)
    try:
        title = request.form.get("title") or ""
        subject = request.form.get("subject") or ""
        scheduled_at_str = request.form.get("scheduled_at")
        email_starting = request.form.get("email_starting")
        email_ending = request.form.get("email_ending")
        
         # Parse & normalize selected_posts
        selected_posts_list = _load_selected_posts(raw_selected)
        if not selected_posts_list:
            return jsonify({"type": "error", "message": "No valid posts selected"}), 400

        # Serialize to a normalized JSON string for DB
        selected_posts_json = json.dumps(selected_posts_list, ensure_ascii=False)


        # Parse scheduled_at datetime
        scheduled_at = None
        if scheduled_at_str and scheduled_at_str.strip():
            try:
                # Handle datetime-local format (YYYY-MM-DDTHH:MM) and convert to expected format
                date_str = scheduled_at_str.strip().replace("T", " ")
                # 1) parse as naive local (the time user picked)
                local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                # 2) attach Europe/Helsinki tz
                local_aware = local_naive.replace(tzinfo=ZoneInfo("Europe/Helsinki"))
                # 3) convert to UTC
                utc_aware = local_aware.astimezone(timezone.utc)
                # 4) store as naive UTC (matches your current model)
                scheduled_at = utc_aware.replace(tzinfo=None)
            except ValueError:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                    }
                )

        status = "scheduled" if scheduled_at else "draft"

        newsletter = Newsletter(
            title=title,
            subject=subject,
            selected_posts=selected_posts_json,
            scheduled_at=scheduled_at,
            status=status,
            created_by=current_user.id,
            email_starting=email_starting,
            email_ending=email_ending,
        )

        db.session.add(newsletter)
        db.session.commit()

        # If no schedule is set, send the newsletter immediately
        if not scheduled_at:
            success, error = send_newsletter_from_custom(newsletter)
            if success:
                newsletter.status = "sent"
                newsletter.sent_at = datetime.now()
                db.session.commit()
                return jsonify(
                    {
                        "type": "success",
                        "message": "Newsletter sent successfully!",
                        "newsletter_id": newsletter.id,
                    }
                )
            else:
                newsletter.error_message = error
                db.session.commit()
                return jsonify(
                    {
                        "type": "error",
                        "message": f"Newsletter created but failed to send: {error}",
                        "newsletter_id": newsletter.id,
                    }
                )

        return jsonify(
            {
                "type": "success",
                "message": "Newsletter scheduled successfully.",
                "newsletter_id": newsletter.id,
            }
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"type": "error", "message": str(e)})


@main.route(
    "/admin/custom-newsletter/<int:newsletter_id>", methods=["GET", "PUT", "DELETE"]
)
@login_required
def manage_custom_newsletter(newsletter_id):
    
    """Manage a specific newsletter"""
    newsletter = db.session.get(Newsletter, newsletter_id)
    print(f"Newsletter found: {newsletter.title}")

    if not newsletter:
        return jsonify({"type": "error", "message": "Newsletter not found"}), 404

    if request.method == "GET":
        
        return jsonify(
            {
                "id": newsletter.id,
                "title": newsletter.title,
                "subject": newsletter.subject,
                "scheduled_at": (
                    utc_naive_to_local(newsletter.scheduled_at)
                    if newsletter.scheduled_at
                    else ""
                ),
                "selected_posts":  newsletter.selected_posts or "[]",
                "email_starting": newsletter.email_starting,
                "email_ending": newsletter.email_ending,
                "status": newsletter.status,
            }
        )

    elif request.method == "PUT":
        try:
            newsletter.title = request.form.get("title")
            newsletter.subject = request.form.get("subject")
            newsletter.selected_posts = request.form.get("selected_posts")
            newsletter.email_starting = request.form.get("email_starting")
            newsletter.email_ending = request.form.get("email_ending")

            scheduled_at_str = request.form.get("scheduled_at")
            if scheduled_at_str and scheduled_at_str.strip():
                try:
                    date_str = scheduled_at_str.strip().replace("T", " ")
                    # 1) parse as naive local (the time user picked)
                    local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                    # 2) attach Europe/Helsinki tz
                    local_aware = local_naive.replace(
                        tzinfo=ZoneInfo("Europe/Helsinki")
                    )
                    # 3) convert to UTC
                    utc_aware = local_aware.astimezone(timezone.utc)
                    # 4) store as naive UTC (matches your current model)
                    scheduled_at = utc_aware.replace(tzinfo=None)
                    newsletter.scheduled_at = scheduled_at
                    newsletter.status = "scheduled"
                except ValueError:
                    return jsonify(
                        {
                            "type": "error",
                            "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                        }
                    )
            else:
                newsletter.scheduled_at = None
                newsletter.status = "draft"

            db.session.commit()

            # If no schedule is set, send the newsletter immediately
            if not newsletter.scheduled_at:
                success, error = send_newsletter_from_custom(newsletter)
                if success:
                    newsletter.status = "sent"
                    newsletter.sent_at = datetime.now()
                    db.session.commit()
                    return jsonify(
                        {"type": "success", "message": "Newsletter sent successfully!"}
                    )
                else:
                    newsletter.error_message = error
                    db.session.commit()
                    return jsonify(
                        {
                            "type": "error",
                            "message": f"Newsletter updated but failed to send: {error}",
                        }
                    )

            return jsonify(
                {"type": "success", "message": "Newsletter updated successfully."}
            )

        except Exception as e:
            db.session.rollback()
            return jsonify({"type": "error", "message": str(e)})

    elif request.method == "DELETE":
        try:
            db.session.delete(newsletter)
            db.session.commit()
            return jsonify(
                {"type": "success", "message": "Newsletter deleted successfully."}
            )
        except Exception as e:
            db.session.rollback()
            return jsonify({"type": "error", "message": str(e)})


@main.route("/admin/custom-newsletter/<int:newsletter_id>/send", methods=["POST"])
@login_required
def send_custom_newsletter(newsletter_id):
    """Send a custom newsletter immediately"""
    try:
        newsletter = db.session.get(Newsletter, newsletter_id)
        if not newsletter:
            return jsonify({"type": "error", "message": "Newsletter not found"}), 404

        success, error = send_newsletter_from_custom(newsletter)

        if success:
            newsletter.status = "sent"
            newsletter.sent_at = datetime.now()
            db.session.commit()
            return jsonify(
                {"type": "success", "message": "Newsletter sent successfully."}
            )
        else:
            newsletter.error_message = error
            db.session.commit()
            return jsonify(
                {"type": "error", "message": f"Failed to send newsletter: {error}"}
            )

    except Exception as e:
        return jsonify({"type": "error", "message": str(e)})


@main.route("/send-custom-newsletter/<int:newsletter_id>")
def send_custom_newsletter_unauthenticated(newsletter_id):
    """Unauthenticated endpoint for cron jobs to send scheduled newsletters"""
    try:
        newsletter = db.session.get(Newsletter, newsletter_id)
        if not newsletter:
            return jsonify({"type": "error", "message": "Newsletter not found"}), 404

        if newsletter.status != "scheduled":
            return (
                jsonify({"type": "error", "message": "Newsletter is not scheduled"}),
                400,
            )

        success, error = send_newsletter_from_custom(newsletter)

        if success:
            newsletter.status = "sent"
            newsletter.sent_at = datetime.now()
            db.session.commit()
            return jsonify(
                {"type": "success", "message": "Newsletter sent successfully."}
            )
        else:
            newsletter.error_message = error
            db.session.commit()
            return jsonify(
                {"type": "error", "message": f"Failed to send newsletter: {error}"}
            )

    except Exception as e:
        return jsonify({"type": "error", "message": str(e)})

def _load_selected_posts(raw: str) -> list[dict]:
    """Parse JSON array string -> list[dict] and keep only allowed fields."""
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []

    cleaned = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # keep only expected keys
        obj = {k: item.get(k) for k in {"id", "title", "snippet", "pub_date", "link"}}
        # basic normalization
        obj["title"] = (obj.get("title") or "Untitled").strip()
        obj["snippet"] = (obj.get("snippet") or "").strip()
        obj["pub_date"] = (obj.get("pub_date") or "").strip()
        link = (obj.get("link") or "").strip()
        if not re.match(r"^https?://", link, flags=re.IGNORECASE):
            link = "#"
        obj["link"] = link
        cleaned.append(obj)
    return cleaned

def send_newsletter_from_custom(newsletter):
    
    try:
        # Settings
        settings = {s.key: s.value for s in Settings.query.all()}
        # ---- Load & clean selected posts from DB (Text column storing JSON string) ----
        raw = newsletter.selected_posts or "[]"
        posts_list = json.loads(raw)                      # list[dict]
        posts = [SimpleNamespace(**p) for p in posts_list]  # dot-access
        if posts:
            print(posts[0].title, posts[0].link, flush=True)

        # ---- Build email body ----
        email_starting = newsletter.email_starting or settings.get(
            "email_starting",
            "<h3>🌟 Hello from Your Team!</h3><p>Here are our selected highlights:</p><hr>",
        )
        email_ending = newsletter.email_ending or settings.get(
            "email_ending",
            "<p><em>Thank you for subscribing!</em></p>",
        )

        post_html = ""
        for p in posts:
            # Sanitize to avoid XSS
            title = html.escape(str(p.title or "Untitled"))
            snippet = html.escape(str(p.snippet or ""))
            link = (p.link or "#").strip()
            pub_date = (p.pub_date or "").strip()

            # Basic link validation
            if not re.match(r"^https?://", link, flags=re.IGNORECASE):
                link = "#"

            date_html = f"<br><small style='color:#6c757d;'>{html.escape(pub_date)}</small>" if pub_date else ""
            post_html += (
                f"<p><strong><a href=\"{link}\" target=\"_blank\" rel=\"noopener noreferrer\">"
                f"{title}</a></strong><br>{snippet}{date_html}</p>"
            )

        if not post_html:
            return False, "No valid posts found"

        email_body = email_starting + post_html + email_ending

        # ---- Send emails (unchanged) ----
        active_emails = NewsletterEmail.query.filter_by(is_active=True).all()
        if not active_emails:
            return False, "No active subscribers found"


        # --- SMTP ---
        smtp_server = settings.get("SMTP_SERVER")
        smtp_port = settings.get("SMTP_PORT")
        smtp_username = settings.get("SMTP_USERNAME")
        smtp_password = settings.get("SMTP_PASSWORD")
        if not all([smtp_server, smtp_port, smtp_username, smtp_password]):
            return False, "SMTP settings incomplete"

        success_count = 0
        failed_count = 0

        for email_entry in active_emails:
            try:
                message = MIMEMultipart()
                message["From"] = smtp_username
                message["To"] = email_entry.email
                message["Subject"] = newsletter.subject or "Newsletter"
                message.attach(MIMEText(email_body, "html"))

                with smtplib.SMTP_SSL(smtp_server, int(smtp_port)) as server:
                    server.login(smtp_username, smtp_password)
                    server.sendmail(smtp_username, email_entry.email, message.as_string())

                success_count += 1
            except Exception as e:
                log_error(f"Error sending to {email_entry.email}: {str(e)}")
                failed_count += 1

        # Persist counts
        newsletter.sent_count = success_count
        newsletter.failed_count = failed_count
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log_error(f"DB commit failed: {e}")

        return True, f"Sent to {success_count} subscribers, failed for {failed_count}"

    except Exception as e:
        log_error(f"send_newsletter_from_custom error: {e}")
        return False, str(e)
    """Remove query params and fragments for consistent comparison."""
    parsed = urlparse(link)
    return urlunparse(parsed._replace(query="", fragment="")).strip().lower()

@main.route("/fetch-rss-posts")
@login_required
def fetch_rss_posts():
    rss_urls = [r.url for r in RssUrl.query.all()]
    if not rss_urls:
        return jsonify({"items": []})
    all_posts = []

    for feed_url in rss_urls:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries:
                # print first entry title and link
                # print(f"Processing entry: {entry.get('title', 'No title')} - {entry.get('link', 'No link')} - {entry.get('pubDate', 'No date')} - {entry.get('description', 'No description')}")

                all_posts.append({
                    "title": entry.get("title", "").strip(),
                    "description": "",
                    "link": entry.get("link", "").strip(),
                    "pub_date": entry.get("published", ""),
                })
        except Exception as e:
            print(f"Error parsing {feed_url}: {e}")

    # Deduplicate by normalized link (most reliable for same content from diff sources)
    unique_posts = {}
    for post in all_posts:
        key = normalize_link(post["link"])
        if key not in unique_posts:
            unique_posts[key] = post
            
    return jsonify({"items": list(unique_posts.values())})

def normalize_link(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip()
    # Remove trailing slashes and unify http(s) case-insensitively
    s = re.sub(r"/+$", "", s)
    return s

@main.route("/fetch-wordpress-posts")
@login_required
def fetch_wordpress_posts():
    """Fetch recent posts from WordPress for newsletter"""
    try:
        settings = {s.key: s.value for s in Settings.query.all()}
        wp_url = settings.get("wp_site_url", "").rstrip("/")
        wp_user = settings.get("wp_username", "")
        wp_app_password = settings.get("wp_app_password", "")

        if not (wp_url and wp_user and wp_app_password):
            return jsonify(
                {"type": "error", "message": "WordPress credentials not configured"}
            )

        # Get posts from WordPress REST API
        api_url = f"{wp_url}/wp-json/wp/v2/posts"
        params = {
            "per_page": 10,  # Get last 10 posts
            "status": "publish",
            "orderby": "date",
            "order": "desc",
        }

        response = requests.get(
            api_url,
            params=params,
            auth=HTTPBasicAuth(wp_user, wp_app_password),
            timeout=10,
        )

        if response.status_code == 200:
            posts = response.json()
            return jsonify(
                {
                    "type": "success",
                    "posts": posts,
                    "message": f"Found {len(posts)} WordPress posts",
                }
            )
        else:
            log_error(
                f"Failed to fetch WordPress posts: {response.status_code} - {response.text}"
            )
            return jsonify(
                {
                    "type": "error",
                    "message": f"Failed to fetch posts: {response.status_code}",
                }
            )

    except Exception as e:
        log_error(f"Error fetching WordPress posts: {str(e)}")
        return jsonify({"type": "error", "message": f"Error: {str(e)}"})


@main.route("/send-newsletter")
def send_newsletter():
    # Check if we should use WordPress posts or local posts
    use_wordpress = request.args.get("source", "local") == "wordpress"
    welcome = (
        Settings.query.filter_by(key="email_starting").first().value
        if Settings.query.filter_by(key="email_starting").first()
        else "<h3>🌟 Hello from Your Team!</h3><p>Here are our blog highlights from this month:</p><hr>"
    )
    email_ending = (
        Settings.query.filter_by(key="email_ending").first().value
        if Settings.query.filter_by(key="email_ending").first()
        else "<p><em>Thank you for subscribing to our newsletter!</em></p>"
    )

    if use_wordpress:
        # Get WordPress posts
        try:
            settings = {s.key: s.value for s in Settings.query.all()}
            wp_url = settings.get("wp_site_url", "").rstrip("/")
            wp_user = settings.get("wp_username", "")
            wp_app_password = settings.get("wp_app_password", "")

            if not (wp_url and wp_user and wp_app_password):
                log_error("WordPress credentials not configured for newsletter")
                return (
                    jsonify(
                        {
                            "message": "WordPress credentials not configured.",
                            "type": "error",
                        }
                    ),
                    500,
                )

            # Get posts from WordPress REST API
            api_url = f"{wp_url}/wp-json/wp/v2/posts"
            now = datetime.now(timezone.utc)
            start_date = datetime(now.year, now.month, 1, tzinfo=timezone.utc)

            params = {
                "per_page": 20,
                "status": "publish",
                "orderby": "date",
                "order": "desc",
                "after": start_date.isoformat(),
            }

            response = requests.get(
                api_url,
                params=params,
                auth=HTTPBasicAuth(wp_user, wp_app_password),
                timeout=10,
            )

            if response.status_code != 200:
                log_error(
                    f"Failed to fetch WordPress posts for newsletter: {response.status_code}"
                )
                return (
                    jsonify(
                        {"message": "Failed to fetch WordPress posts.", "type": "error"}
                    ),
                    500,
                )

            wp_posts = response.json()

            if not wp_posts:
                return (
                    jsonify({"message": "No WordPress posts found for this month."}),
                    404,
                )

            # Build email content from WordPress posts

            post_html = ""

            for post in wp_posts:
                title = post.get("title", {}).get("rendered", "Untitled")
                content = post.get("excerpt", {}).get("rendered", "")
                if not content:
                    # If no excerpt, use first 150 chars of content
                    content = post.get("content", {}).get("rendered", "")
                    content = content[:150] + "..." if len(content) > 150 else content

                # Clean HTML tags from content for email
                

                soup = BeautifulSoup(content, "html.parser")
                clean_content = soup.get_text()
                clean_content = (
                    clean_content[:150] + "..."
                    if len(clean_content) > 150
                    else clean_content
                )

                post_url = post.get("link", "#")
                post_html += f"<p><strong><a href='{post_url}'>{title}</a></strong><br>{clean_content}</p><hr>"

            email_body = welcome + post_html + email_ending

        except Exception as e:
            log_error(f"Error fetching WordPress posts for newsletter: {str(e)}")
            return (
                jsonify(
                    {
                        "message": f"Error fetching WordPress posts: {str(e)}",
                        "type": "error",
                    }
                ),
                500,
            )

    else:
        # Use local blog posts (existing logic)
        now = datetime.now(timezone.utc)
        start_date = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        blogs = Blog.query.filter(
            Blog.created_at >= start_date, Blog.status == "published"
        ).all()

        if not blogs:
            return jsonify({"message": "No blog posts found for this month."}), 404

        # Build email content from local posts
        post_html = ""
        for post in blogs:
            snippet = (
                post.content[:150] + "..." if len(post.content) > 150 else post.content
            )
            url = f"https://yourwebsite.com/blog/{post.id}"  # Adjust this URL to match your route
            post_html += f"<p><strong><a href='{url}'>{post.title}</a></strong><br>{snippet}</p><hr>"

        email_body = welcome + post_html + email_ending

    # SMTP settings
    try:
        smtp_server = Settings.query.filter_by(key="SMTP_SERVER").first().value
        port = int(Settings.query.filter_by(key="SMTP_PORT").first().value)
        sender_email = Settings.query.filter_by(key="SMTP_USERNAME").first().value
        password = Settings.query.filter_by(key="SMTP_PASSWORD").first().value
    except Exception as e:
        log_error(f"Missing or invalid SMTP settings: {str(e)}")
        return (
            jsonify(
                {"message": "SMTP settings are missing or invalid.", "type": "error"}
            ),
            500,
        )

    subject = f"📬 Monthly Blog Highlights - {now.strftime('%B %Y')}"

    # Send email to each active subscriber
    active_emails = NewsletterEmail.query.filter_by(is_active=True).all()
    success, failed = 0, 0

    for email_entry in active_emails:
        receiver_email = email_entry.email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(email_body, "html"))

        try:
            with smtplib.SMTP_SSL(smtp_server, port) as server:
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message.as_string())
            success += 1
        except Exception as e:
            log_error(f"❌ Error sending to {receiver_email}: {e}")
            failed += 1

    source_text = "WordPress" if use_wordpress else "local"
    return jsonify(
        {
            "message": f"✅ Newsletter sent to {success} users, failed for {failed}. Source: {source_text}",
            "month": now.strftime("%B %Y"),
        }
    )


# API routes for CRUD operations
@main.route("/admin/roles")
@login_required
def admin_roles():
    roles = Role.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/roles.html", roles=roles, settings=settings)


@main.route("/api/role", methods=["POST"])
@login_required
def api_create_role():
    try:
        name = request.form.get("name")
        if not name:
            return jsonify({"message": "Name is required", "type": "error"}), 400

        role = Role(name=name)
        db.session.add(role)
        db.session.commit()
        return jsonify({"message": "Role created successfully", "type": "success"})
    except Exception as e:
        return jsonify({"message": str(e), "type": "error"}), 500


@main.route("/api/role/<int:id>", methods=["PUT", "DELETE"])
@login_required
def api_manage_role(id):
    role = db.session.get(Role, id)
    if not role:
        return jsonify({"type": "error", "message": "Role not found"}), 404

    if request.method == "DELETE":
        db.session.delete(role)
        db.session.commit()
        return jsonify({"message": "Role deleted successfully", "type": "success"})

    name = request.form.get("name")
    if not name:
        return jsonify({"message": "Name is required", "type": "error"}), 400

    role.name = name
    db.session.commit()
    return jsonify({"message": "Role updated successfully", "type": "success"})


# API routes for rss url CRUD operations
@main.route("/admin/rss-url")
@login_required
def admin_rss_url():
    # descending order by created_at
    rss_urls = RssUrl.query.order_by(RssUrl.created_at.desc()).all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/rss_url.html", rss_urls=rss_urls, settings=settings)


@main.route("/api/rss-url", methods=["POST"])
@login_required
def api_create_rss_url():
    try:
        url = request.form.get("url")
        if not url:
            return jsonify({"message": "URL is required", "type": "error"}), 400

        # unique URL check
        existing_url = RssUrl.query.filter_by(url=url).first()
        print(f"Checking for existing URL: {url}")

        if existing_url:
            return jsonify({"message": "URL already exists", "type": "error"}), 400

        rss_url = RssUrl(url=url)
        db.session.add(rss_url)
        db.session.commit()
        return jsonify({"message": "RSS URL created successfully", "type": "success"})
    except Exception as e:
        return jsonify({"message": str(e), "type": "error"}), 500


@main.route("/api/rss-url/<int:id>", methods=["PUT", "DELETE"])
@login_required
def api_manage_rss_url(id):
    rss_url = db.session.get(RssUrl, id)
    if not rss_url:
        return jsonify({"type": "error", "message": "RSS URL not found"}), 404

    if request.method == "DELETE":
        db.session.delete(rss_url)
        db.session.commit()
        return jsonify({"message": "RSS URL deleted successfully", "type": "success"})

    url = request.form.get("url")
    if not url:
        return jsonify({"message": "URL is required", "type": "error"}), 400
    
    # unique URL check
    existing_url = RssUrl.query.filter_by(url=url).first()
    print(f"Checking for existing URL: {url}")

    if existing_url:
        return jsonify({"message": "URL already exists", "type": "error"}), 400

    rss_url.url = url
    db.session.commit()
    return jsonify({"message": "RSS URL updated successfully", "type": "success"})


@main.route("/api/user", methods=["POST"])
@login_required
def api_create_user():
    try:
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        phone = request.form.get("phone")
        role_id = request.form.get("role_id")

        if not all([name, email, password]):
            return (
                jsonify(
                    {
                        "message": "Name, email, and password are required",
                        "type": "error",
                    }
                ),
                400,
            )

        user = User(
            name=name, email=email, phone=phone, role_id=role_id if role_id else None
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created successfully", "type": "success"})
    except Exception as e:
        return jsonify({"message": str(e), "type": "error"}), 500


@main.route("/api/user/<int:id>", methods=["PUT", "DELETE"])
@login_required
def api_manage_user(id):
    user = db.session.get(User, id)
    if not user:
        return jsonify({"type": "error", "message": "User not found"}), 404

    if request.method == "DELETE":
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully", "type": "success"})

    user.name = request.form.get("name")
    user.email = request.form.get("email")
    user.phone = request.form.get("phone")
    user.role_id = request.form.get("role_id")

    if request.form.get("password"):
        user.set_password(request.form.get("password"))

    db.session.commit()
    return jsonify({"message": "User updated successfully", "type": "success"})


@main.route("/api/faq", methods=["POST"])
@login_required
def api_create_faq():
    try:
        if request.is_json:
            # Handle JSON request (from query conversion)
            data = request.get_json()
            if not data or "question" not in data or "answer" not in data:
                return (
                    jsonify(
                        {"type": "error", "message": "Question and answer are required"}
                    ),
                    400,
                )

            # Create new FAQ
            faq = FAQ(question=data["question"], answer=data["answer"])
            db.session.add(faq)

            # If query_id is provided, delete the query
            if "query_id" in data:
                query = db.session.get(Query, data["query_id"])
                if query:
                    db.session.delete(query)

            db.session.commit()
            return jsonify({"type": "success", "message": "FAQ created successfully"})
        else:
            # Handle form data request (from FAQ page)
            question = request.form.get("question")
            answer = request.form.get("answer")

            if not all([question, answer]):
                return (
                    jsonify(
                        {"message": "Question and answer are required", "type": "error"}
                    ),
                    400,
                )

            # Create FAQ record
            faq = FAQ(question=question, answer=answer)
            db.session.add(faq)
            db.session.commit()
            return jsonify({"message": "FAQ created successfully", "type": "success"})

    except Exception as e:
        db.session.rollback()
        print(f"Error creating FAQ: {str(e)}")
        return jsonify({"message": str(e), "type": "error"}), 500


def is_url(text: str) -> bool:
    try:
        parsed = urlparse(text)
        return all([parsed.scheme, parsed.netloc])
    except:
        return False


def extract_text_from_file(file_or_url):
    """Extract text from uploaded file, raw text, or URL based on its type."""
    try:
        # Handle string input: URL or raw text
        if isinstance(file_or_url, str):
            if is_url(file_or_url):
                parsed_url = urlparse(file_or_url)
                netloc = parsed_url.netloc.replace("www.", "").lower()
                if netloc in ["youtube.com", "youtu.be"]:
                    return extract_youtube_text(file_or_url)
                return extract_webpage_text(file_or_url)
            else:
                return file_or_url.strip()  # raw text (e.g., from textarea)

        # Handle file uploads
        filename = file_or_url.filename.lower()

        if filename.endswith(".txt"):
            return file_or_url.read().decode("utf-8")

        elif filename.endswith(".pdf"):
            from PyPDF2 import PdfReader

            reader = PdfReader(file_or_url)
            return "\n".join(page.extract_text() or "" for page in reader.pages)

        elif filename.endswith(".docx"):
            from docx import Document

            doc = Document(file_or_url)
            return "\n".join(paragraph.text for paragraph in doc.paragraphs)

        else:
            return None  # unsupported file type

    except Exception as e:
        print(f"Error extracting text: {str(e)}")
        return None


def extract_youtube_text(url):
    """Extract text from YouTube video using transcript."""
    try:
        # Extract video ID from URL
        video_id = None

        # Handle different YouTube URL formats
        if "youtube.com" in url:
            # Handle standard YouTube URLs
            if "v=" in url:
                video_id = re.search(r"v=([^&]+)", url).group(1)
            # Handle YouTube Shorts
            elif "/shorts/" in url:
                video_id = url.split("/shorts/")[1].split("?")[0]
            # Handle YouTube channel URLs
            elif "/channel/" in url or "/user/" in url:
                return None
        elif "youtu.be" in url:
            # Handle shortened YouTube URLs
            video_id = url.split("/")[-1].split("?")[0]

        if not video_id:
            print(f"Could not extract video ID from URL: {url}")
            return None

        try:
            # Try to get transcript
            transcript = YouTubeTranscriptApi.get_transcript(video_id)
            formatter = TextFormatter()
            return formatter.format_transcript(transcript)
        except Exception as e:
            print(f"Error getting transcript for video {video_id}: {str(e)}")
            # Try to get transcript in a different language if available
            try:
                transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)
                # Try to get transcript in English or any available language
                transcript = transcript_list.find_transcript(["en"]).fetch()
                formatter = TextFormatter()
                return formatter.format_transcript(transcript)
            except Exception as e2:
                print(f"Error getting alternative transcript: {str(e2)}")
                return None

    except Exception as e:
        print(f"Error extracting YouTube transcript: {str(e)}")
        return None


def extract_webpage_text(url):
    """Extract text from webpage."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()

        # Get text
        text = soup.get_text()

        # Break into lines and remove leading and trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Drop blank lines
        text = "\n".join(chunk for chunk in chunks if chunk)

        return text
    except Exception as e:
        print(f"Error extracting webpage text: {str(e)}")
        return None


@main.route("/api/faq/<int:faq_id>", methods=["PUT", "DELETE"])
@login_required
def api_manage_faq(faq_id):
    faq = db.session.get(FAQ, faq_id)
    if not faq:
        return jsonify({"type": "error", "message": "FAQ not found"}), 404

    if request.method == "DELETE":
        try:
            db.session.delete(faq)
            db.session.commit()
            return jsonify({"message": "FAQ deleted successfully"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    elif request.method == "PUT":
        data = request.get_json()
        if not data or "question" not in data or "answer" not in data:
            return jsonify({"error": "Question and answer are required"}), 400

        try:
            # Update FAQ content
            faq.question = data["question"]
            faq.answer = data["answer"]
            db.session.commit()

            # Generate embeddings for search
            try:
                generate_and_store_embeddings(faq.question, faq.answer, faq.id, "faq")
            except Exception as e:
                print(f"Error generating embeddings: {e}")
                # Don't fail the whole operation if embeddings fail

            return jsonify({"message": "FAQ updated successfully"})
        except Exception as e:
            db.session.rollback()
            print(f"Error managing FAQ: {e}")
            return jsonify({"error": str(e)}), 500


@main.route("/admin/blogs")
@login_required
def admin_blogs():
    blogs = (
        Blog.query.filter_by(content_type="blog").order_by(Blog.created_at.desc()).all()
    )
    for blog in blogs:
        blog.local_scheduled_at = utc_naive_to_local(blog.scheduled_at)
    return render_template("admin/blogs.html", blogs=blogs)


@main.route("/admin/social-posts")
@login_required
def admin_social_posts():
    social_posts = (
        Blog.query.filter_by(content_type="social")
        .order_by(Blog.created_at.desc())
        .all()
    )
    for post in social_posts:
        post.local_scheduled_at = utc_naive_to_local(post.scheduled_at)
    return render_template("admin/social_posts.html", social_posts=social_posts)


@main.route("/admin/blogs/add", methods=["POST"])
@login_required
def admin_add_blog():
    try:
        title = request.form.get("title")
        content = request.form.get("content")
        scheduled_at_str = request.form.get("scheduled_at")
        post_to_wordpress_flag = bool(request.form.get("post_to_wordpress"))

        # Parse scheduled_at datetime
        scheduled_at = None
        if scheduled_at_str and scheduled_at_str.strip():
            try:
                date_str = scheduled_at_str.strip().replace("T", " ")
                # 1) parse as naive local (the time user picked)
                local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                # 2) attach Europe/Helsinki tz
                local_aware = local_naive.replace(tzinfo=ZoneInfo("Europe/Helsinki"))
                # 3) convert to UTC
                utc_aware = local_aware.astimezone(timezone.utc)
                # 4) store as naive UTC (matches your current model)
                scheduled_at = utc_aware.replace(tzinfo=None)

            except ValueError:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                    }
                )

        status = "published" if not scheduled_at else "scheduled"
        blog = Blog(
            title=title,
            content=content,
            user_id=current_user.id,
            scheduled_at=scheduled_at,
            status=status,
            content_type="blog",
            post_to_wordpress=post_to_wordpress_flag,
        )
        db.session.add(blog)
        db.session.commit()

        # Publish now if needed
        if status == "published" and post_to_wordpress_flag:
            settings = {s.key: s.value for s in Settings.query.all()}
            post_to_wordpress(blog, settings)

        return jsonify({"type": "success", "message": "Blog post created."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"type": "error", "message": str(e)})


@main.route("/api/blog/<int:blog_id>", methods=["GET", "PUT"])
@login_required
def api_blog(blog_id):
    blog = db.session.get(Blog, blog_id)
    if not blog or blog.content_type != "blog":
        return jsonify({"type": "error", "message": "Blog not found"}), 404
    if request.method == "GET":
        return jsonify(
            {
                "title": blog.title,
                "content": blog.content,
                "scheduled_at": (
                    utc_naive_to_local(blog.scheduled_at) if blog.scheduled_at else ""
                ),
                "post_to_wordpress": blog.post_to_wordpress,
            }
        )
    elif request.method == "PUT":
        try:
            blog.title = request.form.get("title")
            blog.content = request.form.get("content")
            scheduled_at_str = request.form.get("scheduled_at")

            # Parse scheduled_at datetime
            scheduled_at = None
            if scheduled_at_str and scheduled_at_str.strip():
                try:
                    date_str = scheduled_at_str.strip().replace("T", " ")
                    # 1) parse as naive local (the time user picked)
                    local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                    # 2) attach Europe/Helsinki tz
                    local_aware = local_naive.replace(
                        tzinfo=ZoneInfo("Europe/Helsinki")
                    )
                    # 3) convert to UTC
                    utc_aware = local_aware.astimezone(timezone.utc)
                    # 4) store as naive UTC (matches your current model)
                    scheduled_at = utc_aware.replace(tzinfo=None)

                except ValueError:
                    return jsonify(
                        {
                            "type": "error",
                            "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                        }
                    )

            blog.scheduled_at = scheduled_at
            blog.post_to_wordpress = bool(request.form.get("post_to_wordpress"))
            blog.status = "published" if not scheduled_at else "scheduled"
            db.session.commit()

            # Publish now if needed
            if (
                blog.status == "published"
                and blog.post_to_wordpress
                and not blog.posted_to_wordpress
            ):
                settings = {s.key: s.value for s in Settings.query.all()}
                post_to_wordpress(blog, settings)

            return jsonify({"type": "success", "message": "Blog post updated."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"type": "error", "message": str(e)})


@main.route("/admin/ai-blogs/add", methods=["POST"])
@login_required
def admin_add_ai_blog():
    try:
        selectTextLink = request.form.get("selectTextLink")
        ai_text_topic = request.form.get("ai_text_topic")
        ai_link_topic = request.form.get("ai_link_topic")
        scheduled_at_str = request.form.get("scheduled_at")
        post_to_wordpress_flag = bool(request.form.get("post_to_wordpress"))

        # Parse scheduled_at datetime
        scheduled_at = None
        if scheduled_at_str and scheduled_at_str.strip():
            try:
                date_str = scheduled_at_str.strip().replace("T", " ")
                # 1) parse as naive local (the time user picked)
                local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                # 2) attach Europe/Helsinki tz
                local_aware = local_naive.replace(tzinfo=ZoneInfo("Europe/Helsinki"))
                # 3) convert to UTC
                utc_aware = local_aware.astimezone(timezone.utc)
                # 4) store as naive UTC (matches your current model)
                scheduled_at = utc_aware.replace(tzinfo=None)
            except ValueError:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                    }
                )

        status = "published" if not scheduled_at else "scheduled"

        if selectTextLink == "text":
            if not ai_text_topic or not ai_text_topic.strip():
                return jsonify(
                    {
                        "type": "error",
                        "message": "Please enter a topic for AI generation",
                    }
                )

            ai_blog = generate_ai_blog(ai_text_topic)
            # log_error(f"AI blog generation for topic: {ai_text_topic}")

            title = ai_blog.get("headline", "AI Generated Blog Post")
            content = ai_blog.get("content", ai_text_topic)
        else:
            if not ai_link_topic or not ai_link_topic.strip():
                return jsonify(
                    {"type": "error", "message": "Please enter a valid link"}
                )

            # check if ai_link_topic is a valid url
            if not is_url(ai_link_topic):
                return jsonify({"type": "error", "message": "Invalid link format"})

            # check if ai_link_topic is youtube link or blog link
            if "youtube.com" in ai_link_topic or "youtu.be" in ai_link_topic:
                extracted_text = extract_youtube_text(ai_link_topic)
            else:
                extracted_text = extract_webpage_text(ai_link_topic)

            if not extracted_text:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Could not extract content from the provided link",
                    }
                )

            ai_blog = generate_ai_blog(extracted_text)
            title = ai_blog.get("headline", "AI Generated Blog Post")
            content = ai_blog.get("content", extracted_text)

        blog = Blog(
            title=title,
            content=content,
            user_id=current_user.id,
            scheduled_at=scheduled_at,
            status=status,
            post_to_wordpress=post_to_wordpress_flag,
        )
        db.session.add(blog)
        db.session.commit()

        # Publish now if needed
        if status == "published" and post_to_wordpress_flag:
            settings = {s.key: s.value for s in Settings.query.all()}
            post_to_wordpress(blog, settings)

        return jsonify(
            {"type": "success", "message": "AI blog post created successfully."}
        )
    except Exception as e:
        db.session.rollback()
        log_error(f"Error creating AI blog post: {str(e)}")
        return jsonify(
            {"type": "error", "message": f"Error creating blog post: {str(e)}"}
        )


@main.route("/api/blog/<int:blog_id>", methods=["POST"])
@login_required
def delete_blog(blog_id):
    try:
        blog = db.session.get(Blog, blog_id)
        if not blog:
            return jsonify({"type": "error", "message": "Blog not found"}), 404
        db.session.delete(blog)
        db.session.commit()
        flash("Blog deleted successfully.", "success")
        return redirect(url_for("main.admin_blogs"))
    except Exception as e:
        db.session.rollback()
        log_error(f"Error deleting blog {blog_id}: {str(e)}")
        flash("Error deleting blog.", "error")
        return redirect(url_for("main.admin_blogs"))


@main.route("/admin/social-posts/add", methods=["POST"])
@login_required
def admin_add_social_post():
    try:
        title = request.form.get("title")
        content = request.form.get("content")
        scheduled_at_str = request.form.get("scheduled_at")
        post_to_linkedin_flag = bool(request.form.get("post_to_linkedin"))
        post_to_twitter_flag = bool(request.form.get("post_to_twitter"))

        # Handle image upload
        image_path = None
        if "image" in request.files:
            image_file = request.files["image"]
            if image_file and image_file.filename:
                # Save image to static/uploads directory
                upload_dir = os.path.join(current_app.static_folder, "uploads")
                os.makedirs(upload_dir, exist_ok=True)
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(upload_dir, filename)
                image_file.save(image_path)
                # Store relative path in database
                image_path = f"uploads/{filename}"

        # Parse scheduled_at datetime
        scheduled_at = None
        if scheduled_at_str and scheduled_at_str.strip():
            try:
                date_str = scheduled_at_str.strip().replace("T", " ")
                # 1) parse as naive local (the time user picked)
                local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                # 2) attach Europe/Helsinki tz
                local_aware = local_naive.replace(tzinfo=ZoneInfo("Europe/Helsinki"))
                # 3) convert to UTC
                utc_aware = local_aware.astimezone(timezone.utc)
                # 4) store as naive UTC (matches your current model)
                scheduled_at = utc_aware.replace(tzinfo=None)
            except ValueError:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                    }
                )

        status = "published" if not scheduled_at else "scheduled"
        social_post = Blog(
            title=title,
            content=content,
            user_id=current_user.id,
            scheduled_at=scheduled_at,
            status=status,
            content_type="social",
            image_path=image_path,
            post_to_linkedin=post_to_linkedin_flag,
            post_to_x=post_to_twitter_flag,
        )
        db.session.add(social_post)
        db.session.commit()

        # Publish now if needed
        if status == "published":
            settings = {s.key: s.value for s in Settings.query.all()}
            if post_to_linkedin_flag:
                post_to_linkedin(social_post, settings)
            if post_to_twitter_flag:
                from app import post_to_twitter

                post_to_twitter(social_post, settings)

        return jsonify({"type": "success", "message": "Social post created."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"type": "error", "message": str(e)})


@main.route("/api/social-post/<int:social_post_id>", methods=["GET", "PUT"])
@login_required
def api_social_post(social_post_id):
    social_post = db.session.get(Blog, social_post_id)
    if not social_post or social_post.content_type != "social":
        return jsonify({"type": "error", "message": "Social post not found"}), 404
    if request.method == "GET":
        return jsonify(
            {
                "title": social_post.title,
                "content": social_post.content,
                "scheduled_at": (
                    utc_naive_to_local(social_post.scheduled_at)
                    if social_post.scheduled_at
                    else ""
                ),
                "post_to_linkedin": social_post.post_to_linkedin,
                # "post_to_twitter": social_post.post_to_x,
                "image_path": (
                    url_for("static", filename=social_post.image_path)
                    if social_post.image_path
                    else None
                ),
                # previewable image path
            }
        )
    elif request.method == "PUT":
        try:
            social_post.title = request.form.get("title")
            social_post.content = request.form.get("content")
            scheduled_at_str = request.form.get("scheduled_at")

            # Handle image upload
            if "image" in request.files:
                image_file = request.files["image"]
                if image_file and image_file.filename:
                    # Save image to static/uploads directory
                    upload_dir = os.path.join(current_app.static_folder, "uploads")
                    os.makedirs(upload_dir, exist_ok=True)
                    filename = secure_filename(image_file.filename)
                    image_path = os.path.join(upload_dir, filename)
                    image_file.save(image_path)
                    # Store relative path in database
                    social_post.image_path = f"uploads/{filename}"

            # Parse scheduled_at datetime
            scheduled_at = None
            if scheduled_at_str and scheduled_at_str.strip():
                try:
                    date_str = scheduled_at_str.strip().replace("T", " ")
                    # 1) parse as naive local (the time user picked)
                    local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                    # 2) attach Europe/Helsinki tz
                    local_aware = local_naive.replace(
                        tzinfo=ZoneInfo("Europe/Helsinki")
                    )
                    # 3) convert to UTC
                    utc_aware = local_aware.astimezone(timezone.utc)
                    # 4) store as naive UTC (matches your current model)
                    scheduled_at = utc_aware.replace(tzinfo=None)
                except ValueError:
                    return jsonify(
                        {
                            "type": "error",
                            "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                        }
                    )

            social_post.scheduled_at = scheduled_at
            social_post.post_to_linkedin = bool(request.form.get("post_to_linkedin"))
            social_post.post_to_x = bool(request.form.get("post_to_twitter"))
            social_post.status = "published" if not scheduled_at else "scheduled"
            db.session.commit()

            # Publish now if needed
            if social_post.status == "published" and (
                social_post.post_to_linkedin or social_post.post_to_x
            ):
                settings = {s.key: s.value for s in Settings.query.all()}
                if social_post.post_to_linkedin and not social_post.posted_to_linkedin:

                    post_to_linkedin(social_post, settings)
                if social_post.post_to_x and not social_post.posted_to_x:
                    from app import post_to_twitter

                    post_to_twitter(social_post, settings)

            return jsonify({"type": "success", "message": "Social post updated."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"type": "error", "message": str(e)})


@main.route("/api/social-post/<int:social_post_id>", methods=["POST"])
@login_required
def delete_social_post(social_post_id):
    try:
        social_post = db.session.get(Blog, social_post_id)
        if not social_post or social_post.content_type != "social":
            return jsonify({"type": "error", "message": "Social post not found"}), 404
        db.session.delete(social_post)
        db.session.commit()
        flash("Social post deleted successfully.", "success")
        return redirect(url_for("main.admin_social_posts"))
    except Exception as e:
        db.session.rollback()
        log_error(f"Error deleting social post {social_post_id}: {str(e)}")
        flash("Error deleting social post.", "error")
        return redirect(url_for("main.admin_social_posts"))


@main.route("/admin/ai-social-posts/add", methods=["POST"])
@login_required
def admin_add_ai_social_post():
    try:
        selectTextLink = request.form.get("selectTextLink")
        ai_text_topic = request.form.get("ai_text_topic")
        ai_link_topic = request.form.get("ai_link_topic")
        scheduled_at_str = request.form.get("scheduled_at")
        post_to_linkedin_flag = bool(request.form.get("post_to_linkedin"))

        # Parse scheduled_at datetime
        scheduled_at = None
        if scheduled_at_str and scheduled_at_str.strip():
            try:
                date_str = scheduled_at_str.strip().replace("T", " ")
                # 1) parse as naive local (the time user picked)
                local_naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                # 2) attach Europe/Helsinki tz
                local_aware = local_naive.replace(tzinfo=ZoneInfo("Europe/Helsinki"))
                # 3) convert to UTC
                utc_aware = local_aware.astimezone(timezone.utc)
                # 4) store as naive UTC (matches your current model)
                scheduled_at = utc_aware.replace(tzinfo=None)
            except ValueError:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Invalid date format. Use YYYY-MM-DD HH:MM",
                    }
                )

        status = "published" if not scheduled_at else "scheduled"

        if selectTextLink == "text":
            if not ai_text_topic or not ai_text_topic.strip():
                return jsonify(
                    {
                        "type": "error",
                        "message": "Please enter a topic for AI generation",
                    }
                )

            ai_blog = generate_ai_social_post(ai_text_topic)
            title = ai_blog.get("headline", "AI Generated Blog Post")
            content = ai_blog.get("content", ai_text_topic)
        else:
            if not ai_link_topic or not ai_link_topic.strip():
                return jsonify(
                    {"type": "error", "message": "Please enter a valid link"}
                )

            # check if ai_link_topic is a valid url
            if not is_url(ai_link_topic):
                return jsonify({"type": "error", "message": "Invalid link format"})

            # check if ai_link_topic is youtube link or blog link
            if "youtube.com" in ai_link_topic or "youtu.be" in ai_link_topic:
                extracted_text = extract_youtube_text(ai_link_topic)
            else:
                extracted_text = extract_webpage_text(ai_link_topic)

            if not extracted_text:
                return jsonify(
                    {
                        "type": "error",
                        "message": "Could not extract content from the provided link",
                    }
                )

            ai_blog = generate_ai_social_post(extracted_text)
            print(ai_blog)
            # print type of ai blog
            print(type(ai_blog))

            # title = ai_blog.get("headline", "AI Generated Post")
            # content = ai_blog.get("content", extracted_text)
            title = content.get("headline", "AI Generated Post")
            content = content.get("content", extracted_text)

        blog = Blog(
            title=title,
            content=content,
            user_id=current_user.id,
            scheduled_at=scheduled_at,
            status=status,
            post_to_linkedin=post_to_linkedin_flag,
            content_type="social",
        )
        db.session.add(blog)
        db.session.commit()

        # Publish now if needed
        if status == "published" and post_to_linkedin_flag:
            settings = {s.key: s.value for s in Settings.query.all()}
            post_to_linkedin(blog, settings)

        return jsonify(
            {"type": "success", "message": "AI social post created successfully."}
        )
    except Exception as e:
        db.session.rollback()
        log_error(f"Error creating AI social post: {str(e)}")
        return jsonify(
            {"type": "error", "message": f"Error creating social post: {str(e)}"}
        )


def generate_ai_blog(content):
    openai_key = db.session.query(Settings).filter_by(key="openai_key").first()
    if not openai_key or not openai_key.value:
        raise Exception("OpenAI API key not configured")

    client = OpenAI(api_key=openai_key.value)

    response = client.chat.completions.create(
        model="gpt-4",
        # messages=[
        #     {
        #         "role": "system",
        #         "content": "You are a professional blog writer. Generate engaging blog content with a catchy headline and well-structured content.",
        #     },
        #     {"role": "user", "content": f"Topic: {content} \n\n Generate a blog post in JSON format with 'headline' and 'content' keys. The content should be in HTML format with proper paragraphs and formatting."},
        # ],
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert blog writer. Use the term 'we' not 'I'. Your job is to generate clear, SEO-friendly blog posts.\n"
                    "Always return your response as a JSON object with the following structure:\n"
                    '{ "headline": "...", "content": "..." }\n'
                    "The 'headline' should be catchy and relevant to the topic.\n"
                    "The 'content' must be well-structured HTML with proper <p> tags, headers, and formatting. "
                    "Avoid markdown. Do not wrap the response in code blocks. Do not include explanation or commentary."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Topic: {content}\n\n"
                    "Please write a full blog article in the format mentioned above. Make sure the output is a valid JSON string."
                ),
            },
        ],
        temperature=0.8,
        max_tokens=2000,
    )

    raw = response.choices[0].message.content
    try:
        # Try to parse as JSON
        parsed = json.loads(raw)
        return parsed
    except json.JSONDecodeError:
        # If JSON parsing fails, try to extract headline and content from the response
        lines = raw.split("\n")
        headline = ""
        content = ""
        in_content = False

        for line in lines:
            line = line.strip()
            if line.startswith('"headline"') or line.startswith("'headline'"):
                headline = line.split(":", 1)[1].strip().strip("\",'")
            elif line.startswith('"content"') or line.startswith("'content'"):
                in_content = True
                content_part = line.split(":", 1)[1].strip().strip("\",'")
                content += content_part
            elif in_content and line:
                content += line

        if not headline or not content:
            # Fallback: use the raw response as content
            headline = "AI Generated Blog Post"
            content = raw

        return {"headline": headline, "content": content}


def generate_ai_social_post(content):
    openai_key = db.session.query(Settings).filter_by(key="openai_key").first()
    linkedin_char_limit = (
        db.session.query(Settings).filter_by(key="linkedin_char_limit").first() or 800
    )
    if not openai_key or not openai_key.value:
        raise Exception("OpenAI API key not configured")

    client = OpenAI(api_key=openai_key.value)

    response = client.chat.completions.create(
        model="gpt-4",
        # messages=[
        #     {
        #         "role": "system",
        #         "content": "You are a professional blog writer. Generate engaging blog content with a catchy headline and well-structured content.",
        #     },
        #     {"role": "user", "content": f"Topic: {content} \n\n Generate a blog post in JSON format with 'headline' and 'content' keys. The content should be in HTML format with proper paragraphs and formatting."},
        # ],
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert linkedin post writer. Use the term 'we' not 'I'. Your job is to generate clear, SEO-friendly social posts.\n"
                    "Always return your response as a JSON object with the following structure:\n"
                    '{ "headline": "...", "content": "..." }\n'
                    "The 'headline' should be catchy and relevant to the topic.\n"
                    "The 'content' must be well-structured linkedin post with proper hashtags and formatting. "
                    "Avoid markdown. Do not wrap the response in code blocks. Do not include explanation or commentary."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Topic: {content}\n\n"
                    "Please write a linkedin post of {linkedin_char_limit.value} characters in the format mentioned above. Make sure the output is a valid JSON string."
                ),
            },
        ],
        temperature=0.8,
        max_tokens=2000,
    )

    raw = response.choices[0].message.content
    try:
        # Try to parse as JSON
        parsed = json.loads(raw)
        return parsed
    except json.JSONDecodeError:
        # If JSON parsing fails, try to extract headline and content from the response
        lines = raw.split("\n")
        headline = ""
        content = ""
        in_content = False

        for line in lines:
            line = line.strip()
            if line.startswith('"headline"') or line.startswith("'headline'"):
                headline = line.split(":", 1)[1].strip().strip("\",'")
            elif line.startswith('"content"') or line.startswith("'content'"):
                in_content = True
                content_part = line.split(":", 1)[1].strip().strip("\",'")
                content += content_part
            elif in_content and line:
                content += line

        if not headline or not content:
            # Fallback: use the raw response as content
            headline = "AI Generated Social Post"
            content = raw

        return {"headline": headline, "content": content}


@main.route("/test-social-scheduler")
@login_required
def test_social_scheduler():
    """Test the social posts scheduler manually"""
    try:
        publish_scheduled_social_posts()
        return jsonify(
            {
                "type": "success",
                "message": "Social posts scheduler test completed. Check logs for details.",
            }
        )
    except Exception as e:
        return jsonify(
            {
                "type": "error",
                "message": f"Social posts scheduler test failed: {str(e)}",
            }
        )


@main.route("/test-linkedin-posting")
@login_required
def test_linkedin_posting():
    """Test LinkedIn posting functionality"""
    try:
        settings = {s.key: s.value for s in Settings.query.all()}

        # Create a test social post
        test_post = Blog(
            title="Test LinkedIn Post",
            content="This is a test post from the application to verify LinkedIn integration.",
            user_id=current_user.id,
            status="published",
            content_type="social",
            post_to_linkedin=True,
            post_to_x=False,
        )
        db.session.add(test_post)
        db.session.commit()

        # Try to post to LinkedIn

        success, error = post_to_linkedin(test_post, settings)

        if success:
            return jsonify(
                {
                    "type": "success",
                    "message": "LinkedIn posting test successful!",
                    "post_id": test_post.linkedin_post_id,
                }
            )
        else:
            return jsonify(
                {"type": "error", "message": f"LinkedIn posting test failed: {error}"}
            )

    except Exception as e:
        return jsonify(
            {"type": "error", "message": f"LinkedIn posting test failed: {str(e)}"}
        )


@main.route("/test-twitter-posting")
@login_required
def test_twitter_posting():
    """Test Twitter posting functionality"""
    try:
        settings = {s.key: s.value for s in Settings.query.all()}

        # Create a test social post
        test_post = Blog(
            title="Test Twitter Post",
            content="This is a test tweet from the application to verify Twitter integration.",
            user_id=current_user.id,
            status="published",
            content_type="social",
            post_to_linkedin=False,
            post_to_x=True,
        )
        db.session.add(test_post)
        db.session.commit()

        # Try to post to Twitter
        from app import post_to_twitter

        success, error = post_to_twitter(test_post, settings)

        if success:
            return jsonify(
                {
                    "type": "success",
                    "message": "Twitter posting test successful!",
                    "post_id": test_post.x_post_id,
                }
            )
        else:
            return jsonify(
                {"type": "error", "message": f"Twitter posting test failed: {error}"}
            )

    except Exception as e:
        return jsonify(
            {"type": "error", "message": f"Twitter posting test failed: {str(e)}"}
        )


@main.route("/check-scheduled-posts")
@login_required
def check_scheduled_posts():
    """Check what scheduled posts exist"""
    try:
        now = datetime.utcnow()  # naive UTC
        scheduled_posts = Blog.query.filter(
            Blog.status == "scheduled", Blog.post_to_wordpress == True
        ).all()

        posts_info = []
        for post in scheduled_posts:
            posts_info.append(
                {
                    "id": post.id,
                    "title": post.title,
                    "scheduled_at": (
                        post.scheduled_at.isoformat() if post.scheduled_at else None
                    ),
                    "is_due": (
                        post.scheduled_at <= now if post.scheduled_at else False
                    ),  # Compare local time with database time
                    "posted_to_wordpress": post.posted_to_wordpress,
                }
            )

        return jsonify(
            {
                "type": "success",
                "current_time": now.isoformat(),
                "scheduled_posts": posts_info,
                "total_scheduled": len(posts_info),
            }
        )
    except Exception as e:
        return jsonify(
            {"type": "error", "message": f"Error checking scheduled posts: {str(e)}"}
        )


@main.route("/trigger-scheduled-post/<int:blog_id>")
@login_required
def trigger_scheduled_post(blog_id):
    """Manually trigger a specific scheduled post"""
    try:
        blog = db.session.get(Blog, blog_id)
        if not blog:
            return jsonify({"type": "error", "message": "Blog not found"}), 404

        if blog.status != "scheduled":
            return jsonify(
                {
                    "type": "error",
                    "message": f"Blog ID {blog_id} is not scheduled (status: {blog.status})",
                }
            )

        if blog.posted_to_wordpress:
            return jsonify(
                {
                    "type": "error",
                    "message": f"Blog ID {blog_id} has already been posted to WordPress",
                }
            )

        # Update status to published
        blog.status = "published"
        db.session.commit()

        # Post to WordPress
        settings = {s.key: s.value for s in Settings.query.all()}
        success, error = post_to_wordpress(blog, settings)

        if success:
            return jsonify(
                {
                    "type": "success",
                    "message": f"Successfully published blog '{blog.title}' to WordPress",
                    "wordpress_post_id": blog.wordpress_post_id,
                }
            )
        else:
            return jsonify(
                {
                    "type": "error",
                    "message": f"Failed to publish blog '{blog.title}' to WordPress: {error}",
                }
            )

    except Exception as e:
        return jsonify(
            {"type": "error", "message": f"Error triggering scheduled post: {str(e)}"}
        )


@main.route("/debug-scheduler")
@login_required
def debug_scheduler():
    """Debug information about the scheduler and scheduled posts"""
    try:
        now = datetime.utcnow()  # naive UTC  # Use local time instead of UTC

        # Get all scheduled posts
        all_scheduled = Blog.query.filter(
            Blog.status == "scheduled", Blog.post_to_wordpress == True
        ).all()

        # Get posts that are due
        due_posts = Blog.query.filter(
            Blog.status == "scheduled",
            Blog.scheduled_at != None,
            Blog.scheduled_at <= now,  # Compare local time with database time
            Blog.post_to_wordpress == True,
            Blog.posted_to_wordpress == False,
        ).all()

        # Get all blogs for comparison
        all_blogs = Blog.query.all()

        debug_info = {
            "current_time": now.isoformat(),
            "total_blogs": len(all_blogs),
            "scheduled_blogs": len(all_scheduled),
            "due_posts": len(due_posts),
            "scheduler_status": "running",  # We assume it's running if this route is accessible
            "scheduled_posts_details": [],
        }

        for post in all_scheduled:
            debug_info["scheduled_posts_details"].append(
                {
                    "id": post.id,
                    "title": post.title,
                    "scheduled_at": (
                        post.scheduled_at.isoformat() if post.scheduled_at else None
                    ),
                    "is_due": (
                        post.scheduled_at <= now if post.scheduled_at else False
                    ),  # Compare local time with database time
                    "posted_to_wordpress": post.posted_to_wordpress,
                    "status": post.status,
                    "post_to_wordpress": post.post_to_wordpress,
                }
            )

        return jsonify({"type": "success", "debug_info": debug_info})

    except Exception as e:
        return jsonify(
            {"type": "error", "message": f"Error getting debug info: {str(e)}"}
        )


@main.route("/test-datetime-comparison")
@login_required
def test_datetime_comparison():
    """Test datetime comparison logic"""
    try:
        now = datetime.utcnow()  # naive UTC  # Use local time instead of UTC

        # Get all scheduled posts
        all_scheduled = Blog.query.filter(
            Blog.status == "scheduled", Blog.post_to_wordpress == True
        ).all()

        comparison_results = []

        for post in all_scheduled:
            scheduled_time = post.scheduled_at
            is_due = scheduled_time <= now if scheduled_time else False

            comparison_results.append(
                {
                    "id": post.id,
                    "title": post.title,
                    "scheduled_at": (
                        scheduled_time.isoformat() if scheduled_time else None
                    ),
                    "current_time": now.isoformat(),
                    "scheduled_time_type": str(type(scheduled_time)),
                    "current_time_type": str(type(now)),
                    "is_due": is_due,
                    "posted_to_wordpress": post.posted_to_wordpress,
                    "status": post.status,
                }
            )

        return jsonify(
            {
                "type": "success",
                "current_time": now.isoformat(),
                "comparison_results": comparison_results,
                "total_scheduled": len(all_scheduled),
            }
        )

    except Exception as e:
        return jsonify(
            {"type": "error", "message": f"Error testing datetime comparison: {str(e)}"}
        )


def get_last_working_day_of_month(year, month):
    """Get the last working day (Monday-Friday) of the given month"""
    # Get the last day of the month
    last_day = calendar.monthrange(year, month)[1]
    last_date = datetime(year, month, last_day)

    # If it's already a weekday (Monday=0, Sunday=6), return it
    if last_date.weekday() < 5:  # Monday to Friday
        return last_date

    # Otherwise, go back to the previous Friday
    days_to_subtract = last_date.weekday() - 4  # 4 = Friday
    if days_to_subtract < 0:
        days_to_subtract += (
            7  # If it's Saturday, go back 1 day; if Sunday, go back 2 days
        )

    return last_date - timedelta(days=days_to_subtract)


@main.route("/send-local-newsletter", methods=["GET"])
def send_newsletter_from_local_posts():
    """Send newsletter using local posts from this month"""
    try:
        # Get this month's posts
        now = datetime.now()
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        blogs = (
            Blog.query.filter(
                Blog.created_at >= start_of_month, Blog.status == "published"
            )
            .order_by(Blog.created_at.desc())
            .limit(10)
            .all()
        )

        if not blogs:
            log_error("No local posts found for this month's newsletter")
            return

        # Get email subscribers
        emails = NewsletterEmail.query.filter_by(is_active=True).all()
        if not emails:
            log_error("No active email subscribers found")
            return

        # Get settings
        settings = {s.key: s.value for s in Settings.query.all()}
        email_starting = settings.get(
            "email_starting",
            "<h3>🌟 Hello from Your Team!</h3><p>Here are our blog highlights from this month:</p><hr>",
        )
        email_ending = settings.get(
            "email_ending",
            "<p><em>Thank you for subscribing to our newsletter!</em></p>",
        )

        # Build email content
        post_html = ""
        for post in blogs:
            snippet = (
                post.content[:200] + "..." if len(post.content) > 200 else post.content
            )
            post_html += f"<p><strong>{post.title}</strong><br>{snippet}</p><hr>"

        email_body = email_starting + post_html + email_ending

        # Send emails
        send_newsletter_emails(emails, "Monthly Newsletter", email_body, settings)

        log_error(f"Recurring local newsletter sent to {len(emails)} subscribers")

    except Exception as e:
        log_error(f"Error sending recurring local newsletter: {str(e)}")


@main.route("/send-wordpress-newsletter", methods=["GET"])
def send_newsletter_from_wordpress_posts():
    """Send newsletter using WordPress posts from this month"""
    try:
        # Get WordPress settings
        settings = {s.key: s.value for s in Settings.query.all()}
        wp_url = settings.get("wp_site_url", "").rstrip("/")

        if not wp_url:
            log_error("WordPress URL not configured")
            return

        # Fetch WordPress posts from this month
        now = datetime.now()
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        api_url = f"{wp_url}/wp-json/wp/v2/posts"
        params = {
            "after": start_of_month.isoformat(),
            "per_page": 10,
            "orderby": "date",
            "order": "desc",
        }

        response = requests.get(api_url, params=params, timeout=10)

        if response.status_code != 200:
            log_error(f"Failed to fetch WordPress posts: {response.status_code}")
            return

        posts = response.json()

        if not posts:
            log_error("No WordPress posts found for this month")
            return

        # Get email subscribers
        emails = NewsletterEmail.query.filter_by(is_active=True).all()
        if not emails:
            log_error("No active email subscribers found")
            return

        # Get email settings
        email_starting = settings.get(
            "email_starting",
            "<h3>🌟 Hello from Your Team!</h3><p>Here are our blog highlights from this month:</p><hr>",
        )
        email_ending = settings.get(
            "email_ending",
            "<p><em>Thank you for subscribing to our newsletter!</em></p>",
        )

        # Build email content
        post_html = ""
        for post in posts:
            title = post.get("title", {}).get("rendered", "Untitled")
            content = post.get("excerpt", {}).get("rendered", "") or post.get(
                "content", {}
            ).get("rendered", "")
            post_url = post.get("link", "#")

            # Clean HTML content
            

            soup = BeautifulSoup(content, "html.parser")
            clean_content = (
                soup.get_text()[:200] + "..."
                if len(soup.get_text()) > 200
                else soup.get_text()
            )

            post_html += f"<p><strong><a href='{post_url}'>{title}</a></strong><br>{clean_content}</p><hr>"

        email_body = email_starting + post_html + email_ending

        # Send emails
        send_newsletter_emails(emails, "Monthly Newsletter", email_body, settings)

        log_error(f"Recurring WordPress newsletter sent to {len(emails)} subscribers")

    except Exception as e:
        log_error(f"Error sending recurring WordPress newsletter: {str(e)}")


def send_newsletter_emails(emails, subject, email_body, settings):
    """Send newsletter emails to subscribers"""
    try:
        smtp_server = settings.get("smtp_server")
        smtp_port = settings.get("smtp_port")
        smtp_username = settings.get("smtp_username")
        smtp_password = settings.get("smtp_password")
        sender_email = settings.get("sender_email")

        if not all(
            [smtp_server, smtp_port, smtp_username, smtp_password, sender_email]
        ):
            log_error("SMTP settings incomplete")
            return

        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender_email

        # Add HTML content
        html_part = MIMEText(email_body, "html")
        msg.attach(html_part)

        # Send to each subscriber
        for email_obj in emails:
            try:
                msg["To"] = email_obj.email

                with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
                    server.starttls()
                    server.login(smtp_username, smtp_password)
                    server.sendmail(sender_email, email_obj.email, msg.as_string())

                log_error(f"Newsletter sent to {email_obj.email}")

            except Exception as e:
                log_error(f"Failed to send newsletter to {email_obj.email}: {str(e)}")

    except Exception as e:
        log_error(f"Error in send_newsletter: {str(e)}")


@main.route("/test-recurring-newsletter/<source>")
@login_required
def test_recurring_newsletter(source):
    """Test the recurring newsletter functionality"""
    try:
        if source not in ["local", "wordpress"]:
            return jsonify({"type": "error", "message": "Invalid source"})

        # Force send the newsletter regardless of date
        log_error(f"Testing recurring newsletter for {source}")

        if source == "local":
            send_newsletter_from_local_posts()
        elif source == "wordpress":
            send_newsletter_from_wordpress_posts()

        return jsonify(
            {
                "type": "success",
                "message": f"Test recurring newsletter for {source} completed. Check logs for details.",
            }
        )

    except Exception as e:
        return jsonify(
            {
                "type": "error",
                "message": f"Error testing recurring newsletter: {str(e)}",
            }
        )


@main.route("/get-last-working-day/<int:year>/<int:month>")
@login_required
def get_last_working_day(year, month):
    """Get the last working day for a specific month (for testing)"""
    try:
        last_working_day = get_last_working_day_of_month(year, month)
        return jsonify(
            {
                "type": "success",
                "year": year,
                "month": month,
                "last_working_day": last_working_day.isoformat(),
                "day_of_week": last_working_day.strftime("%A"),
            }
        )
    except Exception as e:
        return jsonify({"type": "error", "message": str(e)})


@main.route("/publish-scheduled-blogs", methods=["GET"])
def publish_scheduled_blogs():
    try:
        now = datetime.utcnow()  # naive UTC  # Use local time instead of UTC
        settings = {s.key: s.value for s in Settings.query.all()}

        # Find scheduled blogs that are due
        blogs = Blog.query.filter(
            Blog.status == "scheduled",
            Blog.scheduled_at != None,
            Blog.scheduled_at <= now,  # Now comparing local time with database time
            Blog.post_to_wordpress == True,
            Blog.posted_to_wordpress == False,
        ).all()

        for blog in blogs:
            try:
                # Post to WordPress
                success, error = post_to_wordpress(blog, settings)
                if success:
                    blog.status = "published"
                    db.session.commit()
                    log_error(f"Successfully published blog ID {blog.id} to WordPress")

                else:
                    log_error(
                        f"Failed to publish blog ID {blog.id} to WordPress: {error}"
                    )

            except Exception as e:
                log_error(f"Exception processing scheduled blog ID {blog.id}: {str(e)}")

    except Exception as e:
        log_error(f"Scheduler error: {str(e)}")


@main.route("/publish-scheduled-social-posts", methods=["GET"])
def publish_scheduled_social_posts():
    """Publish scheduled social posts to LinkedIn and Twitter"""
    try:
        now = datetime.utcnow()  # naive UTC  # Use local time instead of UTC
        settings = {s.key: s.value for s in Settings.query.all()}

        # Find scheduled social posts that are due
        social_posts = Blog.query.filter(
            Blog.content_type == "social",
            Blog.status == "scheduled",
            Blog.scheduled_at != None,
            Blog.scheduled_at <= now,
        ).all()

        for social_post in social_posts:
            try:
                # Post to LinkedIn if enabled and not already posted
                if social_post.post_to_linkedin and not social_post.posted_to_linkedin:

                    success, error = post_to_linkedin(social_post, settings)
                    if success:
                        log_error(
                            f"Successfully published social post ID {social_post.id} to LinkedIn"
                        )
                    else:
                        log_error(
                            f"Failed to publish social post ID {social_post.id} to LinkedIn: {error}"
                        )

                # Post to Twitter if enabled and not already posted
                if social_post.post_to_x and not social_post.posted_to_x:
                    from app import post_to_twitter

                    success, error = post_to_twitter(social_post, settings)
                    if success:
                        log_error(
                            f"Successfully published social post ID {social_post.id} to Twitter"
                        )
                    else:
                        log_error(
                            f"Failed to publish social post ID {social_post.id} to Twitter: {error}"
                        )

                # Update status to published if all enabled platforms are posted
                if (
                    not social_post.post_to_linkedin or social_post.posted_to_linkedin
                ) and (not social_post.post_to_x or social_post.posted_to_x):
                    social_post.status = "published"
                    db.session.commit()

            except Exception as e:
                log_error(
                    f"Exception processing scheduled social post ID {social_post.id}: {str(e)}"
                )

    except Exception as e:
        log_error(f"Social posts scheduler error: {str(e)}")


@main.route("/publish-scheduled-newsletters", methods=["GET"])
def publish_scheduled_newsletters():
    """Publish scheduled newsletters - unauthenticated endpoint for cron jobs"""
    try:
        now = datetime.utcnow()  # Use local time instead of UTC

        # Find scheduled newsletters that are due
        newsletters = Newsletter.query.filter(
            Newsletter.status == "scheduled",
            Newsletter.scheduled_at != None,
            Newsletter.scheduled_at <= now,
        ).all()

        results = []

        for newsletter in newsletters:
            try:
                success, error = send_newsletter_from_custom(newsletter)

                if success:
                    newsletter.status = "sent"
                    newsletter.sent_at = datetime.now()
                    db.session.commit()
                    results.append(
                        {
                            "newsletter_id": newsletter.id,
                            "title": newsletter.title,
                            "status": "sent",
                            "message": "Newsletter sent successfully",
                        }
                    )
                    log_error(
                        f"Successfully sent scheduled newsletter ID {newsletter.id}: {newsletter.title}"
                    )
                else:
                    newsletter.error_message = error
                    db.session.commit()
                    results.append(
                        {
                            "newsletter_id": newsletter.id,
                            "title": newsletter.title,
                            "status": "failed",
                            "message": f"Failed to send newsletter: {error}",
                        }
                    )
                    log_error(
                        f"Failed to send scheduled newsletter ID {newsletter.id}: {error}"
                    )

            except Exception as e:
                newsletter.error_message = str(e)
                db.session.commit()
                results.append(
                    {
                        "newsletter_id": newsletter.id,
                        "title": newsletter.title,
                        "status": "error",
                        "message": f"Exception: {str(e)}",
                    }
                )
                log_error(
                    f"Exception processing scheduled newsletter ID {newsletter.id}: {str(e)}"
                )

        return jsonify(
            {"type": "success", "processed_count": len(newsletters), "results": results}
        )

    except Exception as e:
        log_error(f"Newsletter scheduler error: {str(e)}")
        return (
            jsonify(
                {"type": "error", "message": f"Newsletter scheduler error: {str(e)}"}
            ),
            500,
        )


@main.route("/upload-image", methods=["POST"])
def upload_image():
    # Use 'file' instead of 'upload'
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    image = request.files["file"]
    filename = image.filename or "upload.jpg"
    settings = {s.key: s.value for s in Settings.query.all()}
    wp_url = settings.get("wp_site_url", "").rstrip("/")
    wp_user = settings.get("wp_username", "")
    wp_app_password = settings.get("wp_app_password", "")
    wp_media_url = wp_url + "/wp-json/wp/v2/media"

    if not (wp_url and wp_user and wp_app_password):
        return jsonify(
            {"type": "error", "message": "WordPress credentials not configured"}
        )  # Detect MIME type
    import mimetypes

    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type:
        mime_type = "image/jpeg"

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": mime_type,
    }

    from requests.auth import HTTPBasicAuth

    response = requests.post(
        wp_media_url,
        headers=headers,
        data=image.read(),
        auth=HTTPBasicAuth(wp_user, wp_app_password),
        timeout=10,
    )

    if response.status_code == 201:
        data = response.json()
        return jsonify({"url": data.get("source_url")})
    else:
        return (
            jsonify(
                {
                    "error": "Failed to upload to WordPress",
                    "status_code": response.status_code,
                    "details": response.text,
                }
            ),
            500,
        )


def post_to_linkedin(blog, settings):
    """Post to LinkedIn company page"""
    try:
        access_token = settings.get("linkedin_access_token")
        org_id = settings.get("linkedin_org_id")
        org_id = f"urn:li:organization:{org_id}"

        if not access_token or not org_id:
            log_error(f"LinkedIn credentials missing for Blog ID: {blog.id}")
            return False, "LinkedIn credentials not set."

        # LinkedIn API endpoint for company posts
        # api_url = f"https://api.linkedin.com/v2/organizations/{org_id}/shares"
        api_url = "https://api.linkedin.com/v2/ugcPosts"

        # Prepare the post data
        blog_description = extract_clean_text(blog.content)
        post_data = {
            "author": f"urn:li:organization:{org_id}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": blog_description},
                    "shareMediaCategory": "NONE",
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0",
        }

        # If blog has an image, upload it first and add to post
        if blog.image_path:
            try:
                # Step 1: Register Image Upload
                upload_request = {
                    "registerUploadRequest": {
                        "owner": org_id,
                        "recipes": ["urn:li:digitalmediaRecipe:feedshare-image"],
                        "serviceRelationships": [
                            {
                                "relationshipType": "OWNER",
                                "identifier": "urn:li:userGeneratedContent",
                            }
                        ],
                    }
                }

                res = requests.post(
                    "https://api.linkedin.com/v2/assets?action=registerUpload",
                    headers=headers,
                    json=upload_request,
                )
                if not res.ok:
                    return {"success": False, "error": res.json()}

                upload_data = res.json()
                upload_url = upload_data["value"]["uploadMechanism"][
                    "com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"
                ]["uploadUrl"]
                image_urn = upload_data["value"]["asset"]

                # Step 2: Upload the image to LinkedIn
                mime_type = mimetypes.guess_type(blog.image_path)[0] or "image/jpeg"
                image_path = os.path.join(current_app.static_folder, blog.image_path)
                with open(image_path, "rb") as image_file:
                    upload_res = requests.put(
                        upload_url, data=image_file, headers={"Content-Type": mime_type}
                    )
                if upload_res.status_code not in (200, 201):
                    return {
                        "success": False,
                        "error": "Image upload failed",
                        "details": upload_res.text,
                    }

                # Step 3: Create Post with Image
                post_data = {
                    "author": org_id,
                    "lifecycleState": "PUBLISHED",
                    "specificContent": {
                        "com.linkedin.ugc.ShareContent": {
                            "shareCommentary": {
                                "text": blog.title + "\n" + blog.content
                            },
                            "shareMediaCategory": "IMAGE",
                            "media": [{"status": "READY", "media": image_urn}],
                        }
                    },
                    "visibility": {
                        "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                    },
                }
            except Exception as e:
                log_error(
                    f"Failed to upload image to LinkedIn for Blog ID {blog.id}: {str(e)}"
                )
                # Continue without image

        else:
            post_data = {
                "author": org_id,
                "lifecycleState": "PUBLISHED",
                "specificContent": {
                    "com.linkedin.ugc.ShareContent": {
                        "shareCommentary": {"text": blog_description},
                        "shareMediaCategory": "NONE",
                    }
                },
                "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
            }

        response = requests.post(api_url, json=post_data, headers=headers, timeout=10)

        if response.status_code in (200, 201):
            post_id = response.json().get("id")
            blog.posted_to_linkedin = True
            blog.linkedin_post_id = str(post_id)
            blog.linkedin_error = None
            db.session.commit()
            return True, None
        else:
            blog.linkedin_error = response.text
            db.session.commit()
            log_error(f"LinkedIn post failed for Blog ID {blog.id}: {response.text}")
            return False, response.text

    except Exception as e:
        blog.linkedin_error = str(e)
        db.session.commit()
        log_error(f"Exception posting to LinkedIn for Blog ID {blog.id}: {str(e)}")
        return False, str(e)


def extract_clean_text(blob):
    """Parses and flattens JSON-like text, or returns cleaned string."""
    if isinstance(blob, dict):
        return " ".join(str(v) for v in blob.values())

    if isinstance(blob, str):
        try:
            # Try to parse JSON string
            parsed = json.loads(blob)
            if isinstance(parsed, dict):
                return " ".join(str(v) for v in parsed.values())
        except json.JSONDecodeError:
            pass

        # Fallback regex-based cleanup
        blob = re.sub(r'[{}"]+', "", blob)  # remove {, }, "
        blob = re.sub(r"\b\w+\s*:\s*", "", blob)  # remove keys like headline:
        # blob = re.sub(r'\s+', ' ', blob).strip()        # collapse spaces
        return blob

    return str(blob).strip()
