from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize DB instance
db = SQLAlchemy()

# User model with admin support
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    phone = db.Column(db.String(20))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Role model for user roles
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

# Frequently Asked Questions
class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    embedding = db.Column(db.Text,nullable=True)  # Store JSON-encoded embedding string

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='draft')  # draft, scheduled, published
    image_path = db.Column(db.String(255), nullable=True)

    # Platform flags
    post_to_wordpress = db.Column(db.Boolean, default=False)
    post_to_linkedin = db.Column(db.Boolean, default=False)
    post_to_x = db.Column(db.Boolean, default=False)

    # Posting status
    posted_to_wordpress = db.Column(db.Boolean, default=False)
    posted_to_linkedin = db.Column(db.Boolean, default=False)
    posted_to_x = db.Column(db.Boolean, default=False)

    # Post IDs (if posted)
    wordpress_post_id = db.Column(db.String(255), nullable=True)
    linkedin_post_id = db.Column(db.String(255), nullable=True)
    x_post_id = db.Column(db.String(255), nullable=True)

    # Errors
    wp_error = db.Column(db.Text, nullable=True)
    linkedin_error = db.Column(db.Text, nullable=True)
    x_error = db.Column(db.Text, nullable=True)

class LinkedInPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    posted = db.Column(db.Boolean, default=False)
    error = db.Column(db.Text, nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    scheduled_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



class TwitterPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    posted = db.Column(db.Boolean, default=False)
    error = db.Column(db.Text, nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    scheduled_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class NewsletterEmail(db.Model):
    __tablename__ = 'newsletter_email'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Settings model to store site-wide configurable text fields
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
