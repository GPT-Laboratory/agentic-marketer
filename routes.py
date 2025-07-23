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
)
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
from datetime import datetime
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
                    "query_id": query.id,
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
    email_entry = NewsletterEmail.query.get_or_404(email_id)
    email_entry.is_active = not email_entry.is_active
    db.session.commit()
    flash(
        f"Email {'activated' if email_entry.is_active else 'deactivated'} successfully.",
        "info",
    )
    return redirect(url_for("main.admin_newsletter_emails"))


@main.route("/admin/newsletter-emails/delete/<int:email_id>", methods=["POST"])
@login_required
def delete_newsletter_email(email_id):
    email_entry = NewsletterEmail.query.get_or_404(email_id)
    db.session.delete(email_entry)
    db.session.commit()
    flash("Email deleted successfully.", "danger")
    return redirect(url_for("main.admin_newsletter_emails"))


@main.route("/send-newsletter")
def send_newsletter():
    # Step 1: Get current month's blog posts
    now = datetime.utcnow()
    start_date = datetime(now.year, now.month, 1)
    blogs = Blog.query.filter(
        Blog.created_at >= start_date, Blog.status == "published"
    ).all()

    if not blogs:
        return jsonify({"message": "No blog posts found for this month."}), 404

    # Step 2: Build email content
    welcome = "<h3>🌟 Hello from Your Team!</h3><p>Here are our blog highlights from this month:</p><hr>"
    post_html = ""
    for post in blogs:
        snippet = (
            post.content[:150] + "..." if len(post.content) > 150 else post.content
        )
        url = f"https://yourwebsite.com/blog/{post.id}"  # Adjust this URL to match your route
        post_html += (
            f"<p><strong><a href='{url}'>{post.title}</a></strong><br>{snippet}</p><hr>"
        )

    email_body = welcome + post_html

    # Step 3: SMTP settings
    try:
        smtp_server = Settings.query.filter_by(key="SMTP_SERVER").first().value
        port = int(Settings.query.filter_by(key="SMTP_PORT").first().value)
        sender_email = Settings.query.filter_by(key="SMTP_USERNAME").first().value
        password = Settings.query.filter_by(key="SMTP_PASSWORD").first().value
    except Exception as e:
        log_error(f"Missing or invalid SMTP settings: {str(e)}")
        return jsonify({"message": "SMTP settings are missing or invalid.", "type": "error"}), 500

    subject = f"📬 Monthly Blog Highlights - {now.strftime('%B %Y')}"

    # Step 4: Send email to each active subscriber
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

    return jsonify(
        {
            "message": f"✅ Newsletter sent to {success} users, failed for {failed}.",
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
    try:
        role = Role.query.get_or_404(id)

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
    except Exception as e:
        return jsonify({"message": str(e), "type": "error"}), 500


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
    try:
        user = User.query.get_or_404(id)

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
    except Exception as e:
        return jsonify({"message": str(e), "type": "error"}), 500


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
                query = Query.query.get(data["query_id"])
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
    try:
        faq = FAQ.query.get_or_404(faq_id)

        if request.method == "DELETE":
            db.session.delete(faq)
            db.session.commit()
            return jsonify({"message": "FAQ deleted successfully"})

        elif request.method == "PUT":
            data = request.get_json()
            if not data or "question" not in data or "answer" not in data:
                return jsonify({"error": "Question and answer are required"}), 400

            # Update FAQ content

            try:
                faq.question = data["question"]
                faq.answer = data["answer"]
                db.session.commit()
                return jsonify({"message": "FAQ updated successfully"})

            except Exception as e:
                db.session.rollback()
                print(f"Error generating embeddings: {e}")
                return jsonify({"error": str(e)}), 500

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
        scheduled_at = request.form.get("scheduled_at")
        post_to_wordpress_flag = bool(request.form.get("post_to_wordpress"))
        status = "published" if not scheduled_at else "scheduled"
        blog = Blog(
            title=title,
            content=content,
            user_id=current_user.id,
            scheduled_at=scheduled_at if scheduled_at else None,
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
    blog = Blog.query.get_or_404(blog_id)
    if request.method == "GET":
        return jsonify({
            "title": blog.title,
            "content": blog.content,
            "scheduled_at": blog.scheduled_at.strftime('%Y-%m-%d %H:%M') if blog.scheduled_at else '',
            "post_to_wordpress": blog.post_to_wordpress,
        })
    elif request.method == "PUT":
        try:
            blog.title = request.form.get("title")
            blog.content = request.form.get("content")
            scheduled_at = request.form.get("scheduled_at")
            blog.scheduled_at = scheduled_at if scheduled_at else None
            blog.post_to_wordpress = bool(request.form.get("post_to_wordpress"))
            blog.status = "published" if not scheduled_at else "scheduled"
            db.session.commit()
            # Publish now if needed
            if blog.status == "published" and blog.post_to_wordpress and not blog.posted_to_wordpress:
                settings = {s.key: s.value for s in Settings.query.all()}
                post_to_wordpress(blog, settings)
            return jsonify({"type": "success", "message": "Blog post updated."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"type": "error", "message": str(e)})
        

@main.route("/api/blog/<int:blog_id>", methods=["POST"])
@login_required
def delete_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    db.session.delete(blog)
    db.session.commit()
    flash("Blog deleted successfully.", "danger")
    return redirect(url_for("main.admin_blogs"))