
# app.py (refactored, session + role-based + optimized dashboard)
from functools import wraps
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import logging
from config import Config
import pytz
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

load_dotenv()

# --- App config ---
app = Flask(__name__, template_folder="templates", static_folder="static")
app.jinja_env.globals.update(now=datetime.utcnow)

# Prefer SECRET_KEY from environment, fallback to Config default
app.config.from_object(Config)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", app.config.get("SECRET_KEY", "dev_secret_key"))

# DATABASE: respectful handling of DATABASE_URL (allow fallback to Config)
db_url = os.environ.get("DATABASE_URL") or app.config.get("SQLALCHEMY_DATABASE_URI")

if db_url:
    # convert postgres:// -> postgresql:// for SQLAlchemy if necessary
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    # only add sslmode=require if not already present and if scheme is postgres/postgresql
    parsed = urlparse(db_url)
    if parsed.scheme in ("postgres", "postgresql"):
        qs = parse_qs(parsed.query)
        if "sslmode" not in qs:
            qs["sslmode"] = ["require"]
            new_query = urlencode({k: v[0] for k, v in qs.items()})
            parsed = parsed._replace(query=new_query)
            db_url = urlunparse(parsed)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    # Fall back to Config's SQLite (good for local dev)
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config.get("SQLALCHEMY_DATABASE_URI", "sqlite:///local_dev.db")

# Engine options & common flags
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session lifetime (optional)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# --- Logging ---
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Context processors ---
@app.context_processor
def inject_current_user():
    # expose session to templates as `current_user`
    return {"current_user": session}

LOCAL_TZ = pytz.timezone("Asia/Kolkata")

@app.context_processor
def inject_datetime():
    def localtime(dt):
        if not dt:
            return ""
        # ensure tz-aware (assume UTC for naive datetimes)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.utc)
        return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
    return dict(localtime=localtime)


# ---------- MODELS ----------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DispatchData(db.Model):
    __tablename__ = "dispatch_data"
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    dispatch_type = db.Column(db.String(20), nullable=False, default="empty")
    parent_dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=True)
    from_role = db.Column(db.String(30), nullable=False)
    to_role = db.Column(db.String(30), nullable=False)
    component = db.Column(db.String(100), nullable=False)
    flc_qty = db.Column(db.Integer, nullable=False)
    component_qty = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), default="Pending")
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[from_user_id], backref="dispatches_sent", lazy=True)
    receiver = db.relationship("User", foreign_keys=[to_user_id], backref="dispatches_received", lazy=True)
    parent = db.relationship("DispatchData", remote_side=[id], backref="children", lazy=True)


class Returned(db.Model):
    __tablename__ = "returned"
    id = db.Column(db.Integer, primary_key=True)
    dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    flc_qty = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    from_user = db.relationship("User", foreign_keys=[from_user_id], lazy=True)
    to_user = db.relationship("User", foreign_keys=[to_user_id], lazy=True)
    dispatch = db.relationship("DispatchData", foreign_keys=[dispatch_id], lazy=True)


class Component(db.Model):
    __tablename__ = 'components'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Added columns referenced in code
    is_fixed = db.Column(db.Boolean, default=False, nullable=False)
    fixed_date = db.Column(db.DateTime, nullable=True)


# ---------- AUTH / ROLE DECORATORS ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Access denied for your role.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return wrapper


# ------------------- AUTH ROUTES -------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Set session and mark permanent
            session["user_id"] = user.id
            session["role"] = user.role
            session["username"] = user.username
            session.permanent = True
            flash("Logged in successfully", "success")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password"
    return render_template("index.html", error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        if not username or not password or not role:
            error = "All fields required."
        elif User.query.filter_by(username=username).first():
            error = "Username already exists."
        else:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            u = User(username=username, password=hashed, role=role)
            try:
                db.session.add(u)
                db.session.commit()
                flash("User created — please login.", "success")
                return redirect(url_for("login"))
            except Exception as e:
                db.session.rollback()
                app.logger.exception("Failed to create user")
                error = f"DB error: {e}"
    return render_template("signup.html", error=error)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ------------------- DASHBOARD -------------------
@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    user_id = session.get('user_id')

    if role == 'Supplier':
        sent_dispatches = DispatchData.query.filter_by(from_role='Supplier').order_by(DispatchData.date_time.desc()).all()
        received_returns = Returned.query.filter_by(to_user_id=user_id).order_by(Returned.date_time.desc()).all()
        return render_template(
            'dashboard.html',
            role=role,
            sent_dispatches=sent_dispatches,
            received_returns=received_returns
        )

    elif role == 'Intermediate':
        received_dispatches = DispatchData.query.filter_by(to_role='Intermediate').order_by(DispatchData.date_time.desc()).all()
        sent_dispatches = DispatchData.query.filter_by(from_role='Intermediate').order_by(DispatchData.date_time.desc()).all()
        return render_template(
            'dashboard.html',
            role=role,
            received_dispatches=received_dispatches,
            sent_dispatches=sent_dispatches
        )

    elif role == 'End User':
        received_dispatches = DispatchData.query.filter_by(to_role='End User').order_by(DispatchData.date_time.desc()).all()
        sent_returns = Returned.query.filter_by(from_user_id=user_id).order_by(Returned.date_time.desc()).all()
        return render_template(
            'dashboard.html',
            role=role,
            received_dispatches=received_dispatches,
            sent_returns=sent_returns
        )

    else:
        flash("Invalid role session. Please log in again.", "danger")
        return redirect(url_for('logout'))


# ------------------- DISPATCH CREATE -------------------
@app.route('/dispatch_create', methods=['GET', 'POST'])
@login_required
@role_required('Supplier', 'Intermediate')
def dispatch_create():
    current_user_id = session["user_id"]
    current_user = User.query.get(current_user_id)
    if not current_user:
        flash("Invalid session user. Please login again.", "danger")
        return redirect(url_for("logout"))

    role = current_user.role
    error = None
    receiver_candidates = []
    end_users = []
    parent_dispatches = []
    components = []

    if role == "Supplier":
        receiver_candidates = User.query.filter_by(role="Intermediate").order_by(User.username).all()
        components = Component.query.order_by(Component.name).all()

    elif role == "Intermediate":
        end_users = User.query.filter_by(role="End User").order_by(User.username).all()
        empties = DispatchData.query.filter_by(to_user_id=current_user_id, dispatch_type="empty", status="Received").all()
        for d in empties:
            consumed = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0))\
                .filter(DispatchData.parent_dispatch_id == d.id).scalar() or 0
            available = d.flc_qty - consumed
            if available > 0:
                parent_dispatches.append((d, available))

    if request.method == "POST":
        app.logger.debug("Dispatch create form data: %s", dict(request.form))
        try:
            component = request.form.get("component", "").strip()
            flc_qty = int(request.form.get("flc_qty", "0"))
            component_qty = int(request.form.get("component_qty", "0"))
            remarks = request.form.get("remarks", "").strip()
        except ValueError:
            error = "Quantities must be integers."

        if not error and (not component or flc_qty <= 0 or component_qty <= 0):
            error = "Please provide component and positive quantities."

        if not error:
            if role == "Supplier":
                try:
                    to_user_id = int(request.form.get("to_user_id"))
                except Exception:
                    error = "Select a valid Intermediate to send empties to."
                    return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, components=components, error=error)

                to_user = User.query.get(to_user_id)
                if not to_user or to_user.role != "Intermediate":
                    error = "Selected receiver is not an Intermediate user."
                    return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, components=components, error=error)

                comp_obj = Component.query.filter_by(name=component).first()
                if not comp_obj:
                    flash("Selected component not found. Please add it first.", "warning")
                    return redirect(url_for("add_component"))

                new_dispatch = DispatchData(
                    from_user_id=current_user_id,
                    to_user_id=to_user_id,
                    dispatch_type="empty",
                    parent_dispatch_id=None,
                    from_role=current_user.role,
                    to_role=to_user.role,
                    component=component,
                    flc_qty=flc_qty,
                    component_qty=component_qty,
                    status="Pending",
                    remarks=remarks,
                    date_time=datetime.utcnow()
                )
                try:
                    db.session.add(new_dispatch)
                    db.session.commit()
                    flash(f"Empty dispatch created (ID: {new_dispatch.id})", "success")
                    return redirect(url_for("dispatch_create"))
                except Exception as e:
                    db.session.rollback()
                    app.logger.exception("Failed to create supplier dispatch")
                    error = f"DB error: {e}"

            elif role == "Intermediate":
                parent_id_raw = request.form.get("parent_dispatch_id", "").strip()
                to_user_raw = request.form.get("to_user_id", "").strip()

                if to_user_raw == "other":
                    end_user_name = request.form.get("end_user_name", "").strip()
                    if not end_user_name:
                        error = "Please enter End User name when selecting Other."
                        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
                    to_user = User.query.filter_by(username=end_user_name, role="End User").first()
                    if not to_user:
                        dummy_pw = bcrypt.generate_password_hash(os.urandom(16)).decode("utf-8")
                        try:
                            to_user = User(username=end_user_name, password=dummy_pw, role="End User")
                            db.session.add(to_user)
                            db.session.commit()
                        except Exception as e:
                            db.session.rollback()
                            app.logger.exception("Failed to create End User")
                            error = f"Failed to create End User: {e}"
                            return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
                    to_user_id = to_user.id
                else:
                    try:
                        to_user_id = int(to_user_raw)
                    except Exception:
                        error = "Select a valid End User."
                        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
                    to_user = User.query.get(to_user_id)
                    if not to_user or to_user.role != "End User":
                        error = "Selected receiver must be an End User."
                        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                if not parent_id_raw:
                    error = "Select which empty dispatch (A→B) batch you are consuming."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                try:
                    parent_id = int(parent_id_raw)
                except Exception:
                    error = "Invalid parent dispatch selected."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                parent = DispatchData.query.get(parent_id)
                if not parent or parent.to_user_id != current_user_id or parent.dispatch_type != "empty" or parent.status != "Received":
                    error = "Selected parent dispatch is not valid."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                consumed_on_parent = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0))\
                    .filter(DispatchData.parent_dispatch_id == parent.id).scalar() or 0
                available = parent.flc_qty - consumed_on_parent
                if flc_qty > available:
                    error = f"Cannot dispatch {flc_qty} FLCs — only {available} empties available from parent dispatch {parent.id}."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                new_dispatch = DispatchData(
                    from_user_id=current_user_id,
                    to_user_id=to_user_id,
                    dispatch_type="filled",
                    parent_dispatch_id=parent.id,
                    from_role=current_user.role,
                    to_role=to_user.role,
                    component=component,
                    flc_qty=flc_qty,
                    component_qty=component_qty,
                    status="Delivered",
                    remarks=remarks,
                    date_time=datetime.utcnow()
                )
                try:
                    db.session.add(new_dispatch)
                    db.session.commit()

                    comp = Component.query.filter_by(name=component).first()
                    if comp:
                        comp.is_fixed = True
                        comp.fixed_date = datetime.utcnow()
                        db.session.commit()

                    flash(f"Filled dispatch created to End User (ID: {new_dispatch.id}) and marked as Delivered.", "success")
                    return redirect(url_for("dispatch_create"))
                except Exception as e:
                    db.session.rollback()
                    app.logger.exception("Failed to create filled dispatch")
                    error = f"DB error: {e}"
            else:
                error = "Your role cannot create dispatches here."

    # Render form depending on role
    if role == "Supplier":
        return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, components=components, error=error)
    elif role == "Intermediate":
        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
    else:
        flash("You don't have permissions to create dispatches.", "warning")
        return redirect(url_for("dashboard"))


# ------------------- RECEIVE -------------------
@app.route("/dispatch_receive", methods=["GET", "POST"])
@login_required
@role_required('Supplier', 'Intermediate')
def dispatch_receive():
    role = session.get("role")
    error = None
    if request.method == "POST":
        app.logger.debug("Receive form data: %s", dict(request.form))
        try:
            dispatch_id = int(request.form.get("dispatch_id"))
        except Exception:
            error = "Invalid dispatch id."
            return render_template("dispatch_receive.html", dispatches=[], error=error)
        dispatch = DispatchData.query.get(dispatch_id)
        if not dispatch:
            error = "Dispatch not found."
        elif dispatch.to_role != role:
            error = "You are not authorized to receive this dispatch (role mismatch)."
        else:
            dispatch.status = "Received"
            db.session.commit()
            flash(f"Dispatch {dispatch_id} marked Received.", "success")
            return redirect(url_for("dispatch_receive"))

    dispatches = DispatchData.query.filter_by(to_role=role).order_by(DispatchData.date_time.desc()).all()
    return render_template("dispatch_receive.html", dispatches=dispatches, error=error)


# ------------------- RETURNS -------------------
@app.route('/returns', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def returns():
    current_user_id = session["user_id"]
    current_user = User.query.get(current_user_id)

    if not current_user or current_user.role != 'Supplier':
        flash("Only suppliers can record returns.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            dispatch_id = int(request.form.get('dispatch_id', 0))
            flc_qty = int(request.form.get('flc_qty', 0))
            remarks = request.form.get('remarks', '').strip()

            dispatch = DispatchData.query.get(dispatch_id)
            if not dispatch:
                flash("Invalid dispatch selected.", "danger")
                return redirect(url_for('returns'))

            total_returned = db.session.query(
                db.func.coalesce(db.func.sum(Returned.flc_qty), 0)
            ).filter_by(dispatch_id=dispatch_id).scalar() or 0

            remaining = dispatch.flc_qty - total_returned
            if remaining <= 0:
                flash("All FLCs from this dispatch have already been returned.", "info")
                return redirect(url_for('returns'))

            if flc_qty <= 0:
                flash("Returned quantity must be positive.", "warning")
                return redirect(url_for('returns'))

            if flc_qty > remaining:
                flash(f"Cannot return {flc_qty} FLCs — only {remaining} available.", "danger")
                return redirect(url_for('returns'))

            new_return = Returned(
                dispatch_id=dispatch.id,
                from_user_id=current_user.id,
                to_user_id=dispatch.from_user_id,
                flc_qty=flc_qty,
                remarks=remarks,
                date_time=datetime.utcnow()
            )
            db.session.add(new_return)

            if flc_qty == remaining:
                dispatch.status = "Returned"

            db.session.commit()
            flash(f"Return of {flc_qty} FLCs recorded successfully.", "success")
            return redirect(url_for('returns'))

        except Exception as e:
            db.session.rollback()
            app.logger.exception("Error recording return")
            flash(f"Failed to record return: {str(e)}", "danger")
            return redirect(url_for('returns'))

    dispatches = DispatchData.query.filter_by(to_role="End User", status="Received").order_by(DispatchData.date_time.desc()).all()
    all_returns = Returned.query.order_by(Returned.date_time.desc()).all()
    return render_template('returns.html', dispatches=dispatches, returns=all_returns)


# ------------------- REPORTS -------------------
@app.route("/reports")
@login_required
def reports():
    user_id = session.get("user_id")
    role = session.get("role")

    cycle_report = []
    pending_returns = []
    remarks_list = []

    if role == "Supplier":
        supplier_dispatches = (
            DispatchData.query
            .filter_by(from_user_id=user_id, dispatch_type="empty")
            .order_by(DispatchData.date_time.desc())
            .all()
        )

        for d in supplier_dispatches:
            returned_qty = (
                db.session.query(db.func.coalesce(db.func.sum(Returned.flc_qty), 0))
                .filter(Returned.dispatch_id == d.id, Returned.to_user_id == user_id)
                .scalar()
                or 0
            )
            pending_qty = max(0, (d.flc_qty or 0) - returned_qty)

            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "-",
                "to_user": d.receiver.username if d.receiver else "-",
                "component": d.component,
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": returned_qty,
                "pending_qty": pending_qty,
                "status": d.status,
                "date_time": d.date_time
            })

            if pending_qty > 0:
                pending_returns.append({
                    "id": d.id,
                    "from_user": d.sender.username if d.sender else "-",
                    "to_user": d.receiver.username if d.receiver else "-",
                    "flc_qty": d.flc_qty or 0,
                    "returned_qty": returned_qty,
                    "pending_qty": pending_qty
                })

            if d.remarks:
                remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})

        supplier_returns = (
            Returned.query
            .filter_by(to_user_id=user_id)
            .order_by(Returned.date_time.desc())
            .all()
        )
        for r in supplier_returns:
            if r.remarks:
                remarks_list.append({"id": r.id, "type": "Return", "remarks": r.remarks})

    elif role == "Intermediate":
        received_from_supplier = (
            DispatchData.query
            .filter_by(to_user_id=user_id, dispatch_type="empty")
            .order_by(DispatchData.date_time.desc())
            .all()
        )

        sent_to_enduser = (
            DispatchData.query
            .filter_by(from_user_id=user_id, dispatch_type="filled")
            .order_by(DispatchData.date_time.desc())
            .all()
        )

        all_dispatches = received_from_supplier + sent_to_enduser

        for d in all_dispatches:
            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "-",
                "to_user": d.receiver.username if d.receiver else "-",
                "component": d.component,
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": 0,
                "pending_qty": 0,
                "status": d.status,
                "date_time": d.date_time
            })
            if d.remarks:
                remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})

        returns_to_supplier = (
            Returned.query
            .filter_by(from_user_id=user_id)
            .order_by(Returned.date_time.desc())
            .all()
        )
        for r in returns_to_supplier:
            if r.remarks:
                remarks_list.append({"id": r.id, "type": "Return", "remarks": r.remarks})

    else:
        all_dispatches = DispatchData.query.order_by(DispatchData.id.desc()).all()
        for d in all_dispatches:
            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "-",
                "to_user": d.receiver.username if d.receiver else "-",
                "component": d.component,
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": 0,
                "pending_qty": 0,
                "status": d.status,
                "date_time": d.date_time
            })

    return render_template(
        "reports.html",
        cycle_report=cycle_report,
        pending_returns=pending_returns,
        remarks=remarks_list,
        role=role
    )


# ------------------- ADD COMPONENT (SUPPLIER SIDE) -------------------
@app.route('/add_component', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def add_component():
    user_id = session.get("user_id")
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash("Component name is required.", "warning")
            return redirect(url_for('add_component'))

        existing = Component.query.filter_by(name=name).first()
        if existing:
            flash("This component already exists.", "warning")
            return redirect(url_for('add_component'))

        new_comp = Component(name=name, description=description)
        try:
            db.session.add(new_comp)
            db.session.commit()
            flash(f"Component '{name}' added successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to add component: {e}", "danger")
        return redirect(url_for('add_component'))

    components = Component.query.order_by(Component.created_at.desc()).all()
    return render_template('add_component.html', components=components)


# ------------------- DB INIT & RUN -------------------
if __name__ == "__main__":
    # Local debug only; production will use gunicorn (Procfile)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
