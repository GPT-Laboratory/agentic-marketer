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
)
from urllib.parse import urlparse

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
from email.mime.text import MIMEText
from app import post_to_wordpress, log_error
from requests.auth import HTTPBasicAuth


# Create blueprint
main = Blueprint("main", __name__)


# Public routes
@main.route("/")
def index():
    faqs = FAQ.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("public/index.html", faqs=faqs, settings=settings)


@main.route("/about")
def about():
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("public/about.html", settings=settings)


@main.route("/contact")
def contact():
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("public/contact.html", settings=settings)


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

    users = User.query.all()
    faqs = FAQ.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template(
        "admin/dashboard.html",
        users=users,
        faqs=faqs,
        settings=settings,
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


@main.route("/admin/roles")
@login_required
def admin_roles():
    roles = Role.query.all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template("admin/roles.html", roles=roles, settings=settings)


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
def admin_newsletter_emails():
    emails = NewsletterEmail.query.order_by(NewsletterEmail.created_at.desc()).all()
    settings = {s.key: s.value for s in Settings.query.all()}
    return render_template(
        "admin/newsletter_emails.html", emails=emails, settings=settings
    )


@main.route("/admin/newsletter-emails/add", methods=["POST"])
@login_required
def add_newsletter_email():
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
    return redirect(url_for("main.admin_newsletter_emails"))


@main.route("/admin/newsletter-emails/toggle/<int:email_id>")
@login_required
def toggle_newsletter_email(email_id):
    email_entry = db.session.get(NewsletterEmail, email_id)
    if not email_entry:
        abort(404)
    email_entry.is_active = not email_entry.is_active
    db.session.commit()
    flash("Email status updated successfully.", "success")
    return redirect(url_for("main.admin_newsletter_emails"))


@main.route("/admin/newsletter-emails/delete/<int:email_id>", methods=["POST"])
@login_required
def delete_newsletter_email(email_id):
    email_entry = db.session.get(NewsletterEmail, email_id)
    if not email_entry:
        abort(404)
    db.session.delete(email_entry)
    db.session.commit()
    flash("Email deleted successfully.", "success")
    return redirect(url_for("main.admin_newsletter_emails"))


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
    email_starting = Settings.query.filter_by(key="email_starting").first().value
    email_ending = Settings.query.filter_by(key="email_ending").first().value
    welcome = email_starting if email_starting else "<h3>🌟 Hello from Your Team!</h3><p>Here are our blog highlights from this month:</p><hr>"

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
                from bs4 import BeautifulSoup

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
    blogs = Blog.query.order_by(Blog.created_at.desc()).all()
    return render_template("admin/blogs.html", blogs=blogs)


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
                scheduled_at = datetime.strptime(
                    scheduled_at_str.strip(), "%Y-%m-%d %H:%M"
                )
                # scheduled_at = datetime.strptime(scheduled_at_str.strip(), "%Y-%m-%dT%H:%M")
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
    if not blog:
        return jsonify({"type": "error", "message": "Blog not found"}), 404
    if request.method == "GET":
        return jsonify(
            {
                "title": blog.title,
                "content": blog.content,
                "scheduled_at": (
                    blog.scheduled_at.strftime("%Y-%m-%d %H:%M")
                    if blog.scheduled_at
                    else ""
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
                    scheduled_at = datetime.strptime(
                        scheduled_at_str.strip(), "%Y-%m-%d %H:%M"
                    )
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
                scheduled_at = datetime.strptime(
                    scheduled_at_str.strip(), "%Y-%m-%d %H:%M"
                )
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
                    "You are an expert blog writer. Your job is to generate clear, SEO-friendly blog posts.\n"
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


@main.route("/test-scheduler")
@login_required
def test_scheduler():
    """Test the scheduler manually"""
    try:
        from app import publish_scheduled_blogs

        publish_scheduled_blogs()
        return jsonify(
            {
                "type": "success",
                "message": "Scheduler test completed. Check logs for details.",
            }
        )
    except Exception as e:
        return jsonify({"type": "error", "message": f"Scheduler test failed: {str(e)}"})


@main.route("/check-scheduled-posts")
@login_required
def check_scheduled_posts():
    """Check what scheduled posts exist"""
    try:
        now = datetime.now().replace(tzinfo=None)  # Use local time instead of UTC
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
        now = datetime.now().replace(tzinfo=None)  # Use local time instead of UTC
        
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
        now = datetime.now().replace(tzinfo=None)  # Use local time instead of UTC
        
        # Get all scheduled posts
        all_scheduled = Blog.query.filter(
            Blog.status == 'scheduled',
            Blog.post_to_wordpress == True
        ).all()
        
        comparison_results = []
        
        for post in all_scheduled:
            scheduled_time = post.scheduled_at
            is_due = scheduled_time <= now if scheduled_time else False
            
            comparison_results.append({
                'id': post.id,
                'title': post.title,
                'scheduled_at': scheduled_time.isoformat() if scheduled_time else None,
                'current_time': now.isoformat(),
                'scheduled_time_type': str(type(scheduled_time)),
                'current_time_type': str(type(now)),
                'is_due': is_due,
                'posted_to_wordpress': post.posted_to_wordpress,
                'status': post.status
            })
        
        return jsonify({
            "type": "success",
            "current_time": now.isoformat(),
            "comparison_results": comparison_results,
            "total_scheduled": len(all_scheduled)
        })
        
    except Exception as e:
        return jsonify({"type": "error", "message": f"Error testing datetime comparison: {str(e)}"})
