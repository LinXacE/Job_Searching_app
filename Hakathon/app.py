import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode="eventlet")

# Improved regex patterns
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PHONE_REGEX = r'^[+]?[0-9]{10,15}$'


# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Admin, businessowner, jobseeker
    method = db.Column(db.String(10), nullable=False)  # email or phone
    value = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    contact_email = db.Column(db.String(100))
    contact_phone = db.Column(db.String(20))
    interests = db.Column(db.String(150))
    education = db.Column(db.Text)
    experience = db.Column(db.Text)
    skills = db.Column(db.Text)
    location = db.Column(db.String(100))
    isadmin = db.Column(db.Boolean, default=False)
    isprimaryadmin = db.Column(db.Boolean, default=False)


class JobPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ownerid = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    category = db.Column(db.String(50))
    jobtype = db.Column(db.String(20))
    timestamp = db.Column(db.String(30))


class Interest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jobseekerid = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    jobpostid = db.Column(db.Integer, db.ForeignKey("job_post.id"), nullable=False)
    approved = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.String(30))


class JobHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jobseekerid = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    jobpostid = db.Column(db.Integer, db.ForeignKey("job_post.id"), nullable=False)
    action = db.Column(db.String(20))
    timestamp = db.Column(db.String(30))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    seeker_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text)
    timestamp = db.Column(db.String(30))


def is_logged_in():
    return "userid" in session


def is_admin():
    if "userid" in session:
        user = db.session.get(User, session["userid"])
        return user and user.isadmin
    return False


def is_primary_admin():
    if "userid" in session:
        user = db.session.get(User, session["userid"])
        return user and user.isprimaryadmin
    return False


# IMPROVED: Better CV completion validation
def is_cv_complete(user):
    """
    Improved CV completion validation that checks for both None and empty strings
    """
    required_fields = [
        user.full_name,
        user.age, 
        user.contact_email,
        user.contact_phone,
        user.experience
    ]
    
    # Check each field is not None and not empty after stripping
    for field in required_fields:
        if not field or (isinstance(field, str) and not field.strip()):
            return False
    
    # Additional validation for age (should be positive number)
    if user.age and (user.age <= 0 or user.age > 120):
        return False
        
    return True


# --- Static/General Routes ---
@app.route("/")
def home_redirect():
    return redirect(url_for("home"))

@app.route("/entry")
def entry():
    return render_template("entry.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/login_method")
def login_method():
    return render_template("login_method.html")


@app.route("/role_select")
def role_select():
    return render_template("role_select.html")


@app.route("/login_method_select")
def login_method_select():
    return render_template("login_method_select.html")


# IMPROVED: Better input validation in login
@app.route("/login/<method>", methods=["GET", "POST"])
def loginmethod(method):
    if request.method == "POST":
        value = request.form.get("value")
        password = request.form.get("password")
        
        # Add input validation
        if not value or not value.strip():
            flash("Email/Phone is required.")
            return redirect(request.url)
        if not password or not password.strip():
            flash("Password is required.")
            return redirect(request.url)
            
        user = User.query.filter_by(value=value.strip(), method=method).first()
        if user and check_password_hash(user.password, password):
            session["userid"] = user.id
            if user.role == "businessowner":
                return redirect(url_for("ownerhome"))
            elif user.role == "jobseeker":
                # IMPROVED: Use the new validation helper
                if not is_cv_complete(user):
                    flash("Please complete your CV before continuing!")
                    return redirect(url_for("seekerprofile"))
                return redirect(url_for("seekerdashboard"))
            elif user.role == "Admin":
                return redirect(url_for("adminusers"))
            flash("Role not recognized.")
            return redirect(url_for("entry"))
        flash("Invalid login credentials.")
        return redirect(request.url)
    return render_template("login_form.html", method=method)


@app.route("/register_role")
def register_role():
    return render_template("register_role.html")


@app.route("/method_select/<role>")
def methodselect(role):
    return render_template("method_select.html", role=role)


# IMPROVED: Better registration validation
@app.route("/register/<role>/<method>", methods=["GET", "POST"])
def register(role, method):
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        value = request.form.get("value", "").strip() 
        password = request.form.get("password", "").strip()

        # Improved input validation
        if not username:
            flash("Username is required")
            return redirect(request.url)
        if len(username) < 3:
            flash("Username must be at least 3 characters")
            return redirect(request.url)
        if not value:
            flash("Email/Phone is required")
            return redirect(request.url)
        if not password:
            flash("Password is required")
            return redirect(request.url)
        if len(password) < 6:
            flash("Password must be at least 6 characters")
            return redirect(request.url)

        # Improved email/phone validation
        if method == "email":
            if not re.match(EMAIL_REGEX, value):
                flash("Please enter a valid email address")
                return redirect(request.url)
        else:  # phone
            if not re.match(PHONE_REGEX, value):
                flash("Please enter a valid phone number (10-15 digits)")
                return redirect(request.url)

        # Check for existing users
        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(request.url)
        if User.query.filter_by(value=value).first():
            flash("Email/Phone already registered!")
            return redirect(request.url)

        try:
            hashed_pw = generate_password_hash(password)
            new_user = User(
                username=username,
                role=role,
                method=method,
                value=value,
                password=hashed_pw,
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login_method_select"))
        except Exception as e:
            db.session.rollback()
            flash("Registration failed. Please try again.")
            return redirect(request.url)

    tmpl = "register_email.html" if method == "email" else "register_phone.html"
    return render_template(tmpl, role=role)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("entry"))


# --- Owner Routes ---
@app.route("/owner/home")
def ownerhome():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    if user.role != "businessowner":
        return redirect(url_for("entry"))

    jobs = JobPost.query.filter_by(ownerid=user.id).all()
    total_jobs = len(jobs)
    total_applicants = 0
    applicants = {}

    for job in jobs:
        interest_records = Interest.query.filter_by(jobpostid=job.id).all()
        seekers = [User.query.get(rec.jobseekerid) for rec in interest_records]
        applicants_count = len([s for s in seekers if s])
        total_applicants += applicants_count
        applicants[job.id] = seekers

    total_interviews = 0
    total_hired = 0

    return render_template(
        "owner_home.html",
        jobs=jobs,
        applicants=applicants,
        total_jobs=total_jobs,
        total_applicants=total_applicants,
        total_interviews=total_interviews,
        total_hired=total_hired,
        owner=user,
    )


@app.route("/owner/profile")
def ownerprofile():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    if user.role != "businessowner":
        return redirect(url_for("entry"))
    jobs = JobPost.query.filter_by(ownerid=user.id).all()
    total_jobs = len(jobs)
    return render_template("owner_profile.html", owner=user, total_jobs=total_jobs)


@app.route("/owner/job_history")
def owner_job_history():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    if user.role != "businessowner":
        return redirect(url_for("entry"))
    jobs = JobPost.query.filter_by(ownerid=user.id).all()
    return render_template("job_details.html", jobs=jobs, owner=user)


@app.route("/owner/job/<int:job_id>")
def job_post_detail(job_id):
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    job = JobPost.query.get_or_404(job_id)
    if job.ownerid != user.id:
        flash("Not authorized to view this job.")
        return redirect(url_for("owner_job_history"))
    interest_records = Interest.query.filter_by(jobpostid=job_id).all()
    applicants = [User.query.get(rec.jobseekerid) for rec in interest_records]
    return render_template("job_detail.html", job=job, applicants=applicants, owner=user)


@app.route("/owner/company-details")
def owner_company_details():
    if not is_logged_in():
        return redirect(url_for("entry"))
    owner = db.session.get(User, session["userid"])
    return render_template("owner_company_details.html", owner=owner)


@app.route("/owner/postjob", methods=["GET", "POST"])
def ownerpostjob():
    if not is_logged_in():
        return redirect(url_for("entry"))
    if request.method == "POST":
        position = request.form.get("position")
        description = request.form.get("description")
        location = request.form.get("location")
        category = request.form.get("category")
        jobtype = request.form.get("jobtype")
        new_job = JobPost(
            ownerid=session["userid"],
            position=position,
            description=description,
            location=location,
            category=category,
            jobtype=jobtype,
            timestamp=datetime.now().isoformat()
        )
        db.session.add(new_job)
        db.session.commit()
        flash("Job posted!")
        return redirect(url_for("ownerhome"))
    return render_template("owner_post_job.html")

@app.route("/owner/shortlist_seeker/<int:job_id>/<int:seeker_id>", methods=["POST"])
def shortlist_seeker(job_id, seeker_id):
    if not is_logged_in():
        return redirect(url_for("entry"))
    
    owner = db.session.get(User, session["userid"])
    if owner.role != "businessowner":
        return redirect(url_for("entry"))
    
    # Update the Interest record to mark as shortlisted
    interest = Interest.query.filter_by(jobpostid=job_id, jobseekerid=seeker_id).first()
    if interest:
        interest.approved = True
        db.session.commit()
        flash("Applicant shortlisted successfully!")
    else:
        flash("Application not found.")
    
    return redirect(url_for("ownerhome"))

@app.route("/owner/chatroom/<int:job_id>", methods=["GET", "POST"])
def owner_chatroom(job_id):
    if not is_logged_in():
        return redirect(url_for("entry"))
    owner = db.session.get(User, session["userid"])
    job = JobPost.query.get_or_404(job_id)
    
    # Gather all interested/applying seekers for the job
    interests = Interest.query.filter_by(jobpostid=job_id).all()
    applicants = []
    for rec in interests:
        seeker = User.query.get(rec.jobseekerid)
        if seeker:
            applicants.append({
                "id": seeker.id,
                "username": seeker.username,
                "position": job.position,
                "cv_link": url_for("view_seeker", seeker_id=seeker.id),
                "chat_enabled": True,
            })
    
    # Select seeker/applicant for chat if present
    seeker_id = request.args.get("seeker_id")
    selected_seeker = User.query.get(int(seeker_id)) if seeker_id else None
    
    # Create consistent room ID format
    room = f"chat_{job_id}_{seeker_id}" if seeker_id else None

    # Enable/disable (use POST and hidden input "chat_action")
    if request.method == "POST" and "chat_action" in request.form:
        action = request.form["chat_action"]
        flash(f"Chat {action} for selected applicant.")

    # Send chat message (if applicant selected)
    if request.method == "POST" and "text" in request.form and seeker_id:
        try:
            msg = Message(
                owner_id=owner.id,
                seeker_id=selected_seeker.id,
                sender_id=owner.id,
                content=request.form["text"],
                timestamp=datetime.now().isoformat()
            )
            db.session.add(msg)
            db.session.commit()
            flash("Message sent.")
        except Exception as e:
            db.session.rollback()
            flash("Failed to send message.")
        return redirect(url_for("owner_chatroom", job_id=job_id, seeker_id=seeker_id))

    # Load messages for the chat box if a seeker/applicant is selected
    messages = []
    if selected_seeker:
        chat_msgs = Message.query.filter_by(owner_id=owner.id, seeker_id=selected_seeker.id).order_by(Message.timestamp).all()
        messages = [
            {"sendername": db.session.get(User, msg.sender_id).username, "text": msg.content, "timestamp": msg.timestamp}
            for msg in chat_msgs
        ]

    return render_template(
        "chat_room.html",
        applicants=applicants,
        selected_seeker=selected_seeker,
        messages=messages,
        room=room,
        user=owner,
    )


# IMPROVED: Better message validation and error handling
@app.route("/owner/messages", methods=["GET", "POST"])
def owner_messages():
    if not is_logged_in():
        return redirect(url_for("entry"))
    owner = db.session.get(User, session["userid"])

    seeker_ids = (
        db.session.query(Message.seeker_id)
        .filter_by(owner_id=owner.id)
        .distinct()
        .all()
    )
    seekers = User.query.filter(User.id.in_([sid[0] for sid in seeker_ids])).all()

    conversations = []
    for seeker in seekers:
        last_message = (
            Message.query.filter_by(owner_id=owner.id, seeker_id=seeker.id)
            .order_by(Message.timestamp.desc())
            .first()
        )
        conversations.append((seeker, last_message.content if last_message else ""))

    selected_seeker = None
    chat_history = []
    seeker_id = request.args.get("seeker_id")
    if seeker_id:
        try:
            selected_seeker = User.query.get(int(seeker_id))
            if selected_seeker:
                chat_history = (
                    Message.query.filter_by(owner_id=owner.id, seeker_id=seeker_id)
                    .order_by(Message.timestamp)
                    .all()
                )
                if request.method == "POST":
                    message_content = request.form.get("message", "").strip()
                    
                    # IMPROVED: Message validation
                    if not message_content:
                        flash("Message cannot be empty.")
                        return redirect(url_for("owner_messages", seeker_id=seeker_id))
                    
                    if len(message_content) > 1000:  # Limit message length
                        flash("Message is too long (max 1000 characters).")
                        return redirect(url_for("owner_messages", seeker_id=seeker_id))
                    
                    try:
                        msg = Message(
                            content=message_content,
                            owner_id=owner.id,
                            seeker_id=seeker_id,
                            sender_id=owner.id,
                            timestamp=datetime.now().isoformat()
                        )
                        db.session.add(msg)
                        db.session.commit()
                        flash("Message sent successfully.")
                    except Exception as e:
                        db.session.rollback()
                        flash("Failed to send message. Please try again.")
                    
                    return redirect(url_for("owner_messages", seeker_id=seeker_id))
        except (ValueError, TypeError):
            flash("Invalid seeker ID.")
            return redirect(url_for("owner_messages"))

    return render_template(
        "owner_messages.html",
        conversations=conversations,
        selected_seeker=selected_seeker,
        chat_history=chat_history,
        owner=owner,
    )


@app.route("/owner/applicants/<jobid>")
def owner_applicants(jobid):
    job = JobPost.query.get_or_404(jobid)
    interests = Interest.query.filter_by(jobpostid=jobid).all()
    seekers = [User.query.get(app.jobseekerid) for app in interests]
    return render_template("owner_applicants.html", interests=interests, job=job, seekers=seekers)


@app.route("/owner/interests/<jobid>")
def ownerinterests(jobid):
    job = JobPost.query.get_or_404(jobid)
    interests = Interest.query.filter_by(jobpostid=jobid).all()
    return render_template("owner_interests.html", interests=interests, job=job)


# --- Jobseeker Routes ---
@app.route("/seeker/dashboard")
def seekerdashboard():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    jobs = JobPost.query.all()
    return render_template("seeker_dashboard.html", jobs=jobs, user=user)


@app.route("/seeker/jobs")
def seekerjobs():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    
    # Get jobs with owner information
    jobs = JobPost.query.filter(JobPost.location.contains(user.location)).all() if user.location else JobPost.query.all()
    job_data = []
    for job in jobs:
        owner = User.query.get(job.ownerid)
        job_info = {
            'id': job.id,
            'position': job.position,
            'description': job.description,
            'location': job.location,
            'category': job.category,
            'jobtype': job.jobtype,
            'owner_name': owner.username if owner else 'Unknown Company'
        }
        job_data.append(job_info)
    
    return render_template("seeker_jobs.html", jobs=job_data, user=user)

@app.route("/seeker/<int:seeker_id>")
def view_seeker(seeker_id):
    seeker = User.query.get_or_404(seeker_id)
    return render_template("view_seeker.html", seeker=seeker)


@app.route("/seeker/applications")
def seekerapplications():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    applications = Interest.query.filter_by(jobseekerid=user.id).all()
    return render_template("seeker_applications.html", applications=applications, user=user)

# IMPROVED: Clearer interest action logic
@app.route("/interest/<int:jobpostid>/<action>", methods=["POST"])
def interest_action(jobpostid, action):
    """
    Handle job seeker actions on applications
    - confirm: Confirm interest in the job (for seeker use)
    - withdraw: Withdraw/remove application
    """
    if not is_logged_in():
        return redirect(url_for("entry"))
        
    user = db.session.get(User, session["userid"])
    if not user or user.role != "jobseeker":
        flash("Access denied.")
        return redirect(url_for("entry"))
    
    # Find the application entry
    app = Interest.query.filter_by(jobseekerid=user.id, jobpostid=jobpostid).first()
    
    if not app:
        flash("Application not found.")
        return redirect(url_for("seekerapplications"))
    
    try:
        if action == "confirm":
            # Seeker confirms they're still interested (optional feature)
            app.timestamp = datetime.now().isoformat()  # Update timestamp
            flash("Interest confirmed!")
        elif action == "withdraw":
            # Withdraw application
            db.session.delete(app)
            flash("Application withdrawn.")
        else:
            flash("Invalid action.")
            return redirect(url_for("seekerapplications"))
            
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash("An error occurred. Please try again.")
        
    return redirect(url_for("seekerapplications"))

# IMPROVED: Duplicate prevention for job applications
@app.route("/seeker/interest/<int:job_id>", methods=["POST"])
def seeker_interest(job_id):
    if not is_logged_in():
        return redirect(url_for("entry"))
        
    user = db.session.get(User, session["userid"])
    if not user or user.role != "jobseeker":
        flash("Access denied.")
        return redirect(url_for("entry"))
    
    # Check if job exists
    job = JobPost.query.get(job_id)
    if not job:
        flash("Job not found.")
        return redirect(url_for("seekerjobs"))
    
    # IMPROVED: Check for existing application
    existing = Interest.query.filter_by(jobseekerid=user.id, jobpostid=job_id).first()
    if existing:
        flash("You have already applied to this job!")
        return redirect(url_for("seekerjobs"))
    
    try:
        # Create new interest/application
        interest = Interest(
            jobseekerid=user.id, 
            jobpostid=job_id, 
            timestamp=datetime.now().isoformat(),
            approved=False  # Initially not approved/shortlisted
        )
        db.session.add(interest)
        db.session.commit()
        flash(f"Successfully applied to {job.position}!")
    except Exception as e:
        db.session.rollback()
        flash("Failed to apply. Please try again.")
    
    return redirect(url_for("seekerjobs"))

@app.route("/seeker/skip/<int:job_id>", methods=["POST"])
def seeker_skip(job_id):
    user = db.session.get(User, session["userid"])
    interest = Interest.query.filter_by(jobseekerid=user.id, jobpostid=job_id).first()
    if interest:
        db.session.delete(interest)
        db.session.commit()
    return redirect(url_for("seekerjobs"))


@app.route("/seeker/profile", methods=["GET", "POST"])
def seekerprofile():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    if request.method == "POST":
        user.full_name = request.form.get("full_name")
        user.age = request.form.get("age")
        user.contact_email = request.form.get("contact_email")
        user.contact_phone = request.form.get("contact_phone")
        user.interests = request.form.get("interests")
        user.education = request.form.get("education")
        user.experience = request.form.get("experience")
        user.skills = request.form.get("skills")
        db.session.commit()
        flash("CV updated. Thank you!")
        return redirect(url_for("seekerdashboard"))
    return render_template("seeker_profile.html", user=user)


# CRITICAL FIX: No more experience data overwrite
@app.route("/seeker/setlocation", methods=["GET", "POST"])
def seekersetlocation():
    if not is_logged_in():
        return redirect(url_for("entry"))

    user = db.session.get(User, session["userid"])
    if request.method == "POST":
        # Update location
        user.location = request.form.get("location")
        
        # FIXED: Don't overwrite experience, only update if provided and not empty
        cv_update = request.form.get("cv")
        if cv_update and cv_update.strip():
            # Only update if experience is empty/None, or append to existing
            if not user.experience or not user.experience.strip():
                user.experience = cv_update.strip()
            else:
                # Optionally append new CV info (or keep existing)
                # user.experience += "\n\n" + cv_update.strip()  # Uncomment to append
                pass  # Keep existing experience intact
        
        db.session.commit()
        flash("Location updated.")
        
        # IMPROVED: Better CV completion validation
        if not is_cv_complete(user):
            flash("Please complete your CV before accessing the dashboard!")
            return redirect(url_for("seekerprofile"))
        return redirect(url_for("seekerdashboard"))

    # Always return a response for GET requests
    return render_template("seeker_set_location.html", user=user)

@app.route("/seeker/history")
def seekerhistory():
    if not is_logged_in():
        return redirect(url_for("entry"))
    user = db.session.get(User, session["userid"])
    history = JobHistory.query.filter_by(jobseekerid=user.id).all()
    records = []
    for record in history:
        job = JobPost.query.get(record.jobpostid)
        records.append({"record": record, "job": job})
    return render_template("seeker_history.html", records=records)

@app.route('/message_seeker/<int:seeker_id>')
def message_seeker(seeker_id):
    seeker = User.query.get(seeker_id)
    if not seeker:
        return "Job seeker not found.", 404
    return render_template('message_seeker.html', seeker=seeker)


# --- Admin Routes ---
@app.route("/admin/login", methods=["GET", "POST"])
def adminlogin():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username, role="Admin").first()
        if user and check_password_hash(user.password, password) and user.isadmin:
            session["userid"] = user.id
            return redirect(url_for("adminusers"))
        flash("Invalid admin credentials.")
        return redirect(request.url)
    return render_template("admin_login.html")


@app.route("/admin/users")
def adminusers():
    if not is_admin():
        return redirect(url_for("adminlogin"))
    users = User.query.all()
    admin = db.session.get(User, session["userid"])
    return render_template("admin_users.html", users=users, admin=admin)


# IMPROVED: Better user deletion with cleanup
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin():
        return redirect(url_for('adminlogin'))
        
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting primary admin
    if user.isprimaryadmin:
        flash("Cannot delete the primary admin.")
        return redirect(url_for('adminusers'))
    
    # Prevent self-deletion
    if user.id == session.get('userid'):
        flash("You cannot delete yourself.")
        return redirect(url_for('adminusers'))
    
    try:
        # IMPROVED: Clean up related records before deletion
        # Delete user's job posts
        JobPost.query.filter_by(ownerid=user.id).delete()
        
        # Delete user's interests/applications
        Interest.query.filter_by(jobseekerid=user.id).delete()
        
        # Delete user's messages
        Message.query.filter(
            (Message.owner_id == user.id) | 
            (Message.seeker_id == user.id) | 
            (Message.sender_id == user.id)
        ).delete()
        
        # Delete user's job history
        JobHistory.query.filter_by(jobseekerid=user.id).delete()
        
        # Finally delete the user
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User "{user.username}" and all related data deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user. Please try again.')
        
    return redirect(url_for('adminusers'))


@app.route('/admin/promote_user/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    if not is_admin():
        return redirect(url_for('adminlogin'))
    user = User.query.get_or_404(user_id)
    user.isadmin = True
    db.session.commit()
    flash(f"User '{user.username}' promoted to admin.")
    return redirect(url_for('adminusers'))

@app.route('/admin/demote_user/<int:user_id>', methods=['POST'])
def demote_user(user_id):
    if not is_admin():
        return redirect(url_for('adminlogin'))
    user = User.query.get_or_404(user_id)
    # Protect primary admin and self-demotion
    if user.isprimaryadmin:
        flash("Cannot demote the primary admin.")
        return redirect(url_for('adminusers'))
    if user.id == session.get('userid'):
        flash("You cannot demote yourself.")
        return redirect(url_for('adminusers'))
    user.isadmin = False
    db.session.commit()
    flash(f"User '{user.username}' demoted from admin.")
    return redirect(url_for('adminusers'))


@app.route("/jobs/map")
def jobs_map():
    jobs = JobPost.query.all()
    return render_template("jobs_map.html", jobs=jobs)


# --- Chat + Video/Voice Call ---
@app.route("/chat/<jobpostid>/<seekerid>")
def chat(jobpostid, seekerid):
    room = f"chat_{jobpostid}_{seekerid}"
    user = db.session.get(User, session["userid"])
    return render_template("chat_room.html", room=room, user=user)


clients = {}


@socketio.on("join")
def handle_join(data):
    username = data["username"]
    room = data["room"]
    join_room(room)
    emit("status", {"msg": f"{username} has entered the room."}, room=room)


@socketio.on("send_message")
def handle_message(data):
    room = data["room"]
    msg = data["msg"]
    username = data["username"]
    emit("receive_message", {"msg": msg, "username": username}, room=room)


@socketio.on("leave")
def handle_leave(data):
    username = data["username"]
    room = data["room"]
    leave_room(room)
    emit("status", {"msg": f"{username} has left the room."}, room=room)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create primary admin if missing
        if not User.query.filter_by(isadmin=True, isprimaryadmin=True).first():
            admin_user = User(
                username="admin",
                role="Admin",
                method="email",
                value="admin@example.com",
                password=generate_password_hash("admin123"),
                isadmin=True,
                isprimaryadmin=True,
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Primary admin account created: admin / admin123")
    socketio.run(app, host="0.0.0.0", port=5000)