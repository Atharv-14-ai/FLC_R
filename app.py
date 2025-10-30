# app.py
from functools import wraps
import os
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import logging
from sqlalchemy import func

# Load .env if present
load_dotenv()

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")
# Secret Key (for session security)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-secret-key")

# Database URL: use Railway's DATABASE_URL if available, else fallback to local SQLite
db_url = os.getenv("DATABASE_URL")
if db_url:
    # Railway sometimes provides postgres:// instead of postgresql://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Logging (debug friendly) ---
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# --- Models ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False)  # 'Supplier', 'Intermediate', 'End User'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class DispatchData(db.Model):
    __tablename__ = "dispatch_data"
    id = db.Column(db.Integer, primary_key=True)

    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    dispatch_type = db.Column(db.String(20), nullable=False, default="empty")  # 'empty' or 'filled'
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

    def __repr__(self):
        return f"<Dispatch {self.id} {self.from_role}->{self.to_role} ({self.dispatch_type}) x{self.flc_qty}>"


class Returned(db.Model):
    __tablename__ = "returned"
    id = db.Column(db.Integer, primary_key=True)
    dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    flc_qty = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Return {self.id} dispatch:{self.dispatch_id} x{self.flc_qty}>"


class Component(db.Model):
    __tablename__ = "components"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500), unique=True, nullable=False)
    description = db.Column(db.String(500), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_fixed = db.Column(db.Boolean, default=False)
    fixed_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Component {self.name} fixed={self.is_fixed}>"
    



class InventoryConfig(db.Model):
    __tablename__ = "inventory_config"
    id = db.Column(db.Integer, primary_key=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    flc_stock = db.Column(db.Integer, nullable=False, default=100)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    supplier = db.relationship("User", backref="inventory_config")






# ---------- AUTH / ROLE DECORATORS ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get("role")
            if user_role not in roles:
                flash("Access denied for your role.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


# ------------------- AUTH ROUTES -------------------
@app.route("/", methods=["GET", "POST"])
def login():
    # If already logged in, go to dashboard
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["role"] = user.role
            session["username"] = user.username
            flash("Logged in successfully", "success")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password"
    return render_template("index.html", error=error)


# Supplier is admin — they will create users via /add_user
@app.route("/add_user", methods=["GET", "POST"])
@login_required
@role_required("Supplier")
def add_user():
    """
    Supplier (admin) can create users of any role, including Supplier.
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()
        if not username or not password or not role:
            error = "All fields required."
        elif User.query.filter_by(username=username).first():
            error = "Username already exists."
        else:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            u = User(username=username, password=hashed, role=role)
            db.session.add(u)
            db.session.commit()
            flash(f"User '{username}' created with role {role}.", "success")
            return redirect(url_for("add_user"))
    return render_template("add_user.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


# ------------------- DASHBOARD -------------------
@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    user_id = session.get('user_id')

    def build_stats(dispatches):
        return {
            "total_dispatches": len(dispatches),
            "pending": len([d for d in dispatches if d.status == "Pending"]),
            "received": len([d for d in dispatches if d.status == "Received"]),
            "returned": len([d for d in dispatches if d.status == "Returned"])
        }

    if role == 'Supplier':
        sent_dispatches = DispatchData.query.filter_by(from_user_id=user_id).order_by(DispatchData.date_time.desc()).all()
        received_returns = Returned.query.filter_by(to_user_id=user_id).order_by(Returned.date_time.desc()).all()
        stats = build_stats(sent_dispatches)
        return render_template("dashboard.html", role=role, sent_dispatches=sent_dispatches,
                               received_returns=received_returns, stats=stats)

    elif role == 'Intermediate':
        received_dispatches = DispatchData.query.filter_by(to_user_id=user_id).order_by(DispatchData.date_time.desc()).all()
        sent_dispatches = DispatchData.query.filter_by(from_user_id=user_id).order_by(DispatchData.date_time.desc()).all()
        stats = build_stats(sent_dispatches)
        return render_template("dashboard.html", role=role, received_dispatches=received_dispatches,
                               sent_dispatches=sent_dispatches, stats=stats)

    else:
        flash("Invalid role session. Please log in again.", "danger")
        return redirect(url_for('logout'))


# ------------------- DISPATCH CREATE -------------------
@app.route('/dispatch_create', methods=['GET', 'POST'])
@login_required
@role_required('Supplier', 'Intermediate')
def dispatch_create():
    user = User.query.get(session['user_id'])
    role = user.role

    components = Component.query.order_by(Component.name.asc()).all()

    # ✅ POST Handling
    if request.method == 'POST':

        # ✅ SUPPLIER: A -> B (Empty Dispatch)
        if role == 'Supplier':
            try:
                to_user_id = int(request.form['to_user'])
                component_id = int(request.form['component_id'])
                flc_qty = int(request.form['flc_qty'])
                component_qty = int(request.form['component_qty'])
                remarks = request.form.get('remarks', '')
            except:
                flash("Invalid entries!", "danger")
                return redirect(url_for('dispatch_create'))

            to_user = User.query.get(to_user_id)
            comp = Component.query.get(component_id)

            if not to_user or to_user.role != "Intermediate":
                flash("Select valid Intermediate!", "danger")
                return redirect(url_for('dispatch_create'))

            new_dispatch = DispatchData(
                from_user_id=user.id,
                to_user_id=to_user_id,
                dispatch_type="empty",
                parent_dispatch_id=None,
                from_role="Supplier",
                to_role="Intermediate",
                component=comp.name,
                flc_qty=flc_qty,
                component_qty=component_qty,
                status="Pending",
                remarks=remarks,
                date_time=datetime.utcnow()
            )
            db.session.add(new_dispatch)
            db.session.commit()
            flash("Dispatch sent to Intermediate ✅", "success")
            return redirect(url_for('dashboard'))

        # ✅ INTERMEDIATE: B -> C (Filled Dispatch)
        if role == 'Intermediate':
            try:
                parent_dispatch_id = int(request.form['parent_dispatch_id'])
                to_user_id = int(request.form['to_user'])
                flc_qty = int(request.form['flc_qty'])
                component_qty = int(request.form['component_qty'])
                remarks = request.form.get('remarks', '')
            except:
                flash("Invalid entries!", "danger")
                return redirect(url_for('dispatch_create'))

            parent = DispatchData.query.get(parent_dispatch_id)
            if not parent:
                flash("Invalid parent dispatch!", "danger")
                return redirect(url_for('dispatch_create'))

            # ✅ Component locked from Supplier dispatch
            component_name = parent.component

            # ✅ Receiver must be End User
            to_user = User.query.get(to_user_id)
            if not to_user or to_user.role != "End User":
                flash("Select valid End User!", "danger")
                return redirect(url_for('dispatch_create'))

            # ✅ Available FLC check (from parent dispatch)
            used = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)) \
                .filter(DispatchData.parent_dispatch_id == parent.id).scalar() or 0
            available = parent.flc_qty - used

            if flc_qty > available:
                flash(f"Only {available} FLCs available!", "danger")
                return redirect(url_for('dispatch_create'))

            # ✅ Create new child dispatch
            new_dispatch = DispatchData(
                from_user_id=user.id,
                to_user_id=to_user_id,
                dispatch_type="filled",
                parent_dispatch_id=parent.id,
                from_role="Intermediate",
                to_role="End User",
                component=component_name,
                flc_qty=flc_qty,
                component_qty=component_qty,
                status="Delivered",
                remarks=remarks,
                date_time=datetime.utcnow()
            )

            db.session.add(new_dispatch)

            # ✅ Only mark parent as processed if all FLCs are used
            if available - flc_qty == 0:
                parent.status = "Processed"

            db.session.commit()

            flash("Filled dispatch delivered ✅", "success")
            return redirect(url_for('dashboard'))

    # ✅ GET Page Render Logic
    if role == 'Supplier':
        intermediates = User.query.filter_by(role="Intermediate").all()
        return render_template(
            'dispatch_create.html',
            role=role,
            users=intermediates,
            components=components
        )

    elif role == 'Intermediate':
        end_users = User.query.filter_by(role="End User").all()

        # ✅ Fetch all received or partially used dispatches
        received_dispatches = DispatchData.query.filter(
            DispatchData.to_user_id == user.id,
            DispatchData.status.in_(["Received", "Processed"])  # both allowed
        ).all()

        parent_list = []
        for d in received_dispatches:
            consumed = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)) \
                .filter(DispatchData.parent_dispatch_id == d.id).scalar()
            available = d.flc_qty - consumed
            if available > 0:
                parent_list.append((d, available))

        return render_template(
            'dispatch_create.html',
            role=role,
            users=end_users,
            parent_dispatches=parent_list
        )

    flash("Unauthorized role!", "danger")
    return redirect(url_for('dashboard'))



# ------------------- RECEIVE -------------------
@app.route("/dispatch_receive", methods=["GET", "POST"])
@login_required
@role_required('Supplier', 'Intermediate')
def dispatch_receive():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    role = session.get("role")
    error = None

    # ✅ Handle "Mark Received"
    if request.method == "POST":
        try:
            dispatch_id = int(request.form.get("dispatch_id"))
        except Exception:
            error = "Invalid dispatch id."
            return render_template("dispatch_receive.html", dispatches=[], error=error)

        dispatch = DispatchData.query.get(dispatch_id)

        if not dispatch:
            error = "Dispatch not found."
        elif dispatch.to_user_id != user_id:
            error = "You are not authorized to receive this dispatch."
        else:
            # Mark as received only if not already handled
            if dispatch.status not in ["Received", "Returned"]:
                dispatch.status = "Received"
                db.session.commit()
                flash(f"Dispatch {dispatch_id} marked Received ✅", "success")
            else:
                flash(f"Dispatch {dispatch_id} already marked as {dispatch.status}", "info")

            return redirect(url_for("dispatch_receive"))

    # ✅ Filter dispatches properly by role
    if role == "Supplier":
        # Supplier should see only dispatches that are sent TO them (C → A)
        # and NOT already returned or received
        dispatches = (
            DispatchData.query.filter(
                DispatchData.to_user_id == user_id,
                DispatchData.status == "Pending"  # Only pending to receive
            )
            .order_by(DispatchData.date_time.desc())
            .all()
        )

    elif role == "Intermediate":
        # Intermediate sees only those addressed to them (A → B)
        # and still pending confirmation
        dispatches = (
            DispatchData.query.filter(
                DispatchData.to_user_id == user_id,
                DispatchData.status == "Pending"
            )
            .order_by(DispatchData.date_time.desc())
            .all()
        )
    else:
        dispatches = []

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


# ------------------- COMPONENTS (Supplier manages) -------------------
# ------------------- MANAGE USERS (Supplier-only) -------------------
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def manage_users():
    """
    Supplier (admin) can:
     - view Intermediate and End User lists separately
     - add Intermediate or End User
     - edit or delete users (edit/delete handled by separate routes)
    """
    error = None

    if request.method == 'POST':
        # create new user (Supplier can add only Intermediate or End User)
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        # Basic validation
        if not username or not password or role not in ('Intermediate', 'End User'):
            flash('All fields required and role must be Intermediate or End User.', 'danger')
            return redirect(url_for('manage_users'))

        # duplicate username
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'warning')
            return redirect(url_for('manage_users'))

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash(f"✅ User '{username}' created as {role}.", 'success')
        return redirect(url_for('manage_users'))

    # GET: show separate lists
    intermediates = User.query.filter_by(role='Intermediate').order_by(User.username).all()
    end_users = User.query.filter_by(role='End User').order_by(User.username).all()

    return render_template('manage_users.html', intermediates=intermediates, end_users=end_users)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def edit_user(user_id):
    """
    Edit a non-Supplier user. Supplier cannot edit other Supplier accounts here.
    """
    user = User.query.get_or_404(user_id)

    # Prevent editing Supplier accounts from this UI
    if user.role == 'Supplier':
        flash('Cannot edit Supplier account here.', 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        if not username or role not in ('Intermediate', 'End User'):
            flash('Invalid input. Username required and role must be Intermediate or End User.', 'danger')
            return redirect(url_for('edit_user', user_id=user.id))

        # check duplicate username (exclude current user)
        existing = User.query.filter(User.username == username, User.id != user.id).first()
        if existing:
            flash('Username already taken by another account.', 'warning')
            return redirect(url_for('edit_user', user_id=user.id))

        user.username = username
        user.role = role

        # update password only if provided
        if password:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.commit()
        flash('✅ User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('Supplier')
def delete_user(user_id):
    """
    Delete a non-Supplier user. Use POST for safety.
    """
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'warning')
        return redirect(url_for('manage_users'))

    if user.role == 'Supplier':
        flash('Cannot delete Supplier account.', 'danger')
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash('✅ User deleted successfully.', 'success')
    return redirect(url_for('manage_users'))




# ------------------- REPORTS -------------------
@app.route("/reports")
@login_required
def reports():
    user_id = session.get("user_id")
    role = session.get("role")

    cycle_report = []
    pending_returns = []
    remarks_list = []
    supplier_returns = []  # ✅ added for supplier return entries

    if role == "Supplier":
        # Supplier dispatches (A → B)
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

        # Supplier returns (End User → Supplier)
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
        # Intermediate dispatches and returns
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
        # Admin view (all dispatches)
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

    # ✅ Pass supplier_returns to template
    return render_template(
        "reports.html",
        cycle_report=cycle_report,
        pending_returns=pending_returns,
        remarks=remarks_list,
        role=role,
        supplier_returns=supplier_returns
    )





# ------------------- COMPONENT MANAGEMENT (Supplier Only) -------------------
@app.route('/components')
@login_required
@role_required('Supplier')
def components():
    comps = Component.query.order_by(Component.created_at.desc()).all()
    return render_template("components.html", components=comps)


@app.route('/add_component', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def add_component():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash("Component name required!", "danger")
            return redirect(url_for('add_component'))

        if Component.query.filter_by(name=name).first():
            flash("Component with this name already exists!", "warning")
            return redirect(url_for('add_component'))

        comp = Component(name=name, description=description, created_by=session.get("user_id"))
        db.session.add(comp)
        db.session.commit()
        flash("✅ Component added successfully!", "success")
        return redirect(url_for('components'))

    return render_template("add_component.html")


@app.route('/edit_component/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def edit_component(id):
    component = Component.query.get_or_404(id)

    if request.method == 'POST':
        component.name = request.form.get('name', '').strip()
        component.description = request.form.get('description', '').strip()

        db.session.commit()
        flash("✅ Component updated!", "success")
        return redirect(url_for('components'))

    return render_template("edit_component.html", component=component)


@app.route('/delete_component/<int:id>')
@login_required
@role_required('Supplier')
def delete_component(id):
    component = Component.query.get_or_404(id)
    db.session.delete(component)
    db.session.commit()
    flash("🗑️ Component deleted!", "info")
    return redirect(url_for('components'))


# ------------------- SUPPLIER ANALYTICS REPORTS (Charts) -------------------
# ✅ API DATA ENDPOINTS FOR CHARTS

@app.route("/api/report/dispatch-status")
@login_required
@role_required("Supplier")
def api_dispatch_status():
    data = db.session.query(
        DispatchData.status,
        db.func.count(DispatchData.id)
    ).filter_by(from_user_id=session['user_id']).group_by(DispatchData.status).all()

    result = {row[0]: row[1] for row in data}
    return jsonify(result)


@app.route("/api/report/intermediate-performance")
@login_required
@role_required("Supplier")
def api_intermediate_performance():
    data = db.session.query(
        User.username,
        db.func.count(DispatchData.id)
    ).join(DispatchData, DispatchData.to_user_id == User.id) \
     .filter(DispatchData.from_user_id == session['user_id'],
             User.role == "Intermediate") \
     .group_by(User.username).all()

    result = {row[0]: row[1] for row in data}
    return jsonify(result)


@app.route("/api/report/enduser-consumption")
@login_required
@role_required("Supplier")
def api_enduser_consumption():
    data = db.session.query(
        User.username,
        db.func.sum(DispatchData.flc_qty)
    ).join(User, DispatchData.to_user_id == User.id) \
     .filter(DispatchData.dispatch_type == "filled") \
     .group_by(User.username).all()

    result = {row[0]: row[1] or 0 for row in data}
    return jsonify(result)


@app.route("/api/report/component-movement")
@login_required
@role_required("Supplier")
def api_component_movement():
    data = db.session.query(
        DispatchData.component,
        db.func.sum(DispatchData.component_qty)
    ).group_by(DispatchData.component).all()

    result = {row[0]: row[1] or 0 for row in data}
    return jsonify(result)


@app.route("/api/report/flc-cycle")
@login_required
@role_required("Supplier")
def api_flc_cycle():
    total_sent = db.session.query(db.func.sum(DispatchData.flc_qty)) \
        .filter_by(from_user_id=session['user_id']).scalar() or 0

    total_returned = db.session.query(db.func.sum(Returned.flc_qty)) \
        .filter_by(to_user_id=session['user_id']).scalar() or 0

    in_cycle = total_sent - total_returned

    result = {
        "sent": total_sent,
        "returned": total_returned,
        "in_cycle": max(in_cycle, 0)
    }
    return jsonify(result)


@app.route("/api/report/pending-returns")
@login_required
@role_required("Supplier")
def api_pending_returns():
    data = db.session.query(
        DispatchData.id,
        DispatchData.flc_qty,
        db.func.coalesce(db.func.sum(Returned.flc_qty), 0)
    ).outerjoin(Returned, Returned.dispatch_id == DispatchData.id) \
     .filter(DispatchData.from_user_id == session['user_id']).group_by(DispatchData.id).all()

    result = {d[0]: int(max(0, (d[1] or 0) - (d[2] or 0))) for d in data}
    return jsonify(result)


# Add these imports at top if not already:
from datetime import timedelta
import json

# Add this route somewhere after your other routes (keeping consistent style)
@app.route("/reports/analytics")
@login_required
@role_required("Supplier")
def supplier_analytics():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash("Session expired or user not found. Please log in again.", "danger")
        return redirect(url_for("logout"))

    # ✅ BASIC STATS
    total_dispatches = DispatchData.query.filter_by(from_user_id=user.id).count()
    pending = DispatchData.query.filter_by(from_user_id=user.id, status="Pending").count()
    received = DispatchData.query.filter_by(from_user_id=user.id, status="Received").count()
    returned = DispatchData.query.filter_by(from_user_id=user.id, status="Returned").count()

    stats = {
        "total_dispatches": total_dispatches,
        "pending": pending,
        "received": received,
        "returned": returned,
    }

    # ✅ TREND DATA — Past 7 days
    today = datetime.utcnow().date()
    labels, dispatch_series, returns_series = [], [], []

    for i in range(7):
        day = today - timedelta(days=i)
        labels.append(day.strftime("%b %d"))

        dispatch_series.append(
            DispatchData.query.filter(
                DispatchData.from_user_id == user.id,
                func.date(DispatchData.date_time) == day
            ).count()
        )

        returns_series.append(
            Returned.query.filter(
                Returned.to_user_id == user.id,  # Supplier receives returns
                func.date(Returned.date_time) == day
            ).count()
        )

    labels.reverse()
    dispatch_series.reverse()
    returns_series.reverse()

    # ✅ STATUS DONUT DATA
    status_map = {}
    status_rows = (
        db.session.query(DispatchData.status, func.count())
        .filter_by(from_user_id=user.id)
        .group_by(DispatchData.status)
        .all()
    )
    for s, c in status_rows:
        status_map[s] = c

    # ✅ FETCH INVENTORY (dynamic base FLC)
    inventory = InventoryConfig.query.filter_by(supplier_id=user.id).first()
    BASELINE_SUPPLIER_FLC = inventory.flc_stock if inventory else 0

    # ✅ INVENTORY FLOW LOGIC
    # Supplier → Intermediate
    total_sent_to_intermediate = (
        db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0))
        .filter(DispatchData.from_user_id == user.id)
        .scalar()
    )

    # Intermediate → End User
    intermediate_ids = [u.id for u in User.query.filter_by(role="Intermediate").all()]
    total_sent_to_enduser = (
        db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0))
        .filter(DispatchData.from_user_id.in_(intermediate_ids))
        .scalar()
    )

    # End User → Supplier (Returns)
    total_returned_to_supplier = (
        db.session.query(func.coalesce(func.sum(Returned.flc_qty), 0))
        .filter(Returned.to_user_id == user.id)
        .scalar()
    )

    # ✅ FLC count distribution
    flc_at_supplier = max(BASELINE_SUPPLIER_FLC - total_sent_to_intermediate + total_returned_to_supplier, 0)
    flc_at_intermediate = max(total_sent_to_intermediate - total_sent_to_enduser, 0)
    flc_at_enduser = max(total_sent_to_enduser - total_returned_to_supplier, 0)

    flc_summary = {
        "at_supplier": flc_at_supplier,
        "at_intermediate": flc_at_intermediate,
        "at_enduser": flc_at_enduser,
        "total_sent_to_intermediate": total_sent_to_intermediate,
        "total_sent_to_enduser": total_sent_to_enduser,
        "total_returned_to_supplier": total_returned_to_supplier,
        "total_flc_system": BASELINE_SUPPLIER_FLC,
    }

    chart_data = {
        "labels": labels,
        "dispatch_series": dispatch_series,
        "returns_series": returns_series,
        "status_map": status_map,
    }

    return render_template(
        "supplier_analytics.html",
        stats=stats,
        chart_data=json.dumps(chart_data),
        flc_summary=flc_summary,
    )



@app.before_request
def init_supplier_inventory():
    suppliers = User.query.filter_by(role="Supplier").all()
    for sup in suppliers:
        if not InventoryConfig.query.filter_by(supplier_id=sup.id).first():
            inv = InventoryConfig(supplier_id=sup.id, flc_stock=100)
            db.session.add(inv)
    db.session.commit()




@app.route("/update_inventory", methods=["POST"])
@login_required
@role_required("Supplier")
def update_inventory():
    """Allow supplier to add new FLCs to their inventory."""
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash("Session expired or user not found. Please log in again.", "danger")
        return redirect(url_for("logout"))

    try:
        add_qty = int(request.form.get("add_qty", 0))
    except ValueError:
        flash("Invalid input! Please enter a valid number.", "danger")
        return redirect(url_for("supplier_analytics"))

    if add_qty <= 0:
        flash("Quantity must be greater than zero.", "warning")
        return redirect(url_for("supplier_analytics"))

    # Fetch or create supplier inventory record
    inventory = InventoryConfig.query.filter_by(supplier_id=user.id).first()
    if not inventory:
        inventory = InventoryConfig(supplier_id=user.id, flc_stock=add_qty)
        db.session.add(inventory)
        msg = f"Inventory initialized with {add_qty} FLCs ✅"
    else:
        inventory.flc_stock += add_qty
        msg = f"Added {add_qty} new FLCs to your inventory ✅"

    db.session.commit()
    flash(msg, "success")

    return redirect(url_for("supplier_analytics"))



# ------------------- DB INIT & RUN -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
