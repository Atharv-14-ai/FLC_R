# app.py
from functools import wraps
import os
from datetime import datetime, timedelta  # Make sure timedelta is here
from collections import defaultdict

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import logging
import json  # Also make sure json is imported

from sqlalchemy import func

# Load .env if present
load_dotenv()

# --- App config ---
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    # "postgresql://postgres:1234@localhost:5432/flc"
    "postgresql://postgres:eKJOgGccJZtXKcUvrcEDkUteFbuzRsqh@switchback.proxy.rlwy.net:40253/railway"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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
    to_end_user_id = db.Column(db.Integer, db.ForeignKey('end_users.id'), nullable=True)

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

# In your models (add this to Returned model)
class Returned(db.Model):
    __tablename__ = "returned"
    id = db.Column(db.Integer, primary_key=True)
    dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    from_end_user_id = db.Column(db.Integer, db.ForeignKey('end_users.id'), nullable=True)
    flc_qty = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    # FIXED: Add proper relationship names
    dispatch_rel = db.relationship('DispatchData', foreign_keys=[dispatch_id], backref='returns_received')
    from_user_rel = db.relationship('User', foreign_keys=[from_user_id], backref='returns_sent')
    to_user_rel = db.relationship('User', foreign_keys=[to_user_id], backref='returns_received')
    from_end_user_rel = db.relationship('EndUser', foreign_keys=[from_end_user_id], backref='returns_made')

    def __repr__(self):
        return f"<Return {self.id} dispatch:{self.dispatch_id} x{self.flc_qty}>"


class Component(db.Model):
    __tablename__ = "components"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500), unique=True, nullable=False)
    description = db.Column(db.String(500), nullable=True)
    flc_stock = db.Column(db.Integer, nullable=False, default=100)   # New column
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_fixed = db.Column(db.Boolean, default=False)
    fixed_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Component {self.name} fixed={self.is_fixed}>"
    


class EndUser(db.Model):
    __tablename__ = 'end_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



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
    user = User.query.get(session.get('user_id'))
    if not user:
        flash("User session invalid. Please log in again.", "danger")
        return redirect(url_for('login'))

    role = user.role
    components = Component.query.order_by(Component.name.asc()).all()

    if request.method == 'POST':
        # ✅ Supplier → Intermediate
        if role == 'Supplier':
            try:
                to_user_id = int(request.form['to_user'])
                component_ids = request.form.getlist('component_id[]')
                flc_qtys = request.form.getlist('flc_qty[]')
                comp_qtys = request.form.getlist('component_qty[]')
                remarks_list = request.form.getlist('remarks[]')
            except Exception:
                flash("Invalid input!", "danger")
                return redirect(url_for('dispatch_create'))

            to_user = User.query.get(to_user_id)
            if not to_user or to_user.role != "Intermediate":
                flash("Please select a valid Intermediate!", "danger")
                return redirect(url_for('dispatch_create'))

            for cid, fqty, cqty, rem in zip(component_ids, flc_qtys, comp_qtys, remarks_list):
                comp = Component.query.get(int(cid))
                if not comp:
                    continue

                new_dispatch = DispatchData(
                    from_user_id=user.id,
                    to_user_id=to_user_id,
                    dispatch_type="empty",
                    parent_dispatch_id=None,
                    from_role="Supplier",
                    to_role="Intermediate",
                    component=comp.name,
                    flc_qty=int(fqty),
                    component_qty=int(cqty),
                    status="Pending",
                    remarks=rem,
                    date_time=datetime.utcnow()
                )
                db.session.add(new_dispatch)

            db.session.commit()
            flash("✅ Multiple FLCs dispatched to Intermediate successfully!", "success")
            return redirect(url_for('dashboard'))

        # ✅ Intermediate → End User (multiple dispatches)
# ✅ Intermediate → End User (Enhanced: multiple parent dispatches + multiple end users)
        elif role == 'Intermediate':
            try:
                parent_ids = request.form.getlist('parent_dispatch_id[]')
                all_data = json.loads(request.form.get('dispatch_data'))  # hidden JSON field we'll build via JS
            except Exception:
                flash("Invalid submission!", "danger")
                return redirect(url_for('dispatch_create'))

            for parent_id, dispatch_group in all_data.items():
                parent = DispatchData.query.get(int(parent_id))
                if not parent:
                    continue

                for entry in dispatch_group:
                    end_user_id = int(entry['end_user_id'])
                    flc_qty = int(entry['flc_qty'])
                    comp_qty = int(entry['component_qty'])
                    remarks = entry.get('remarks', '')

                    end_user = EndUser.query.get(end_user_id)
                    if not end_user:
                        continue

                    used = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)) \
                        .filter(DispatchData.parent_dispatch_id == parent.id).scalar() or 0
                    available = parent.flc_qty - used

                    if flc_qty > available:
                        flash(f"⚠️ Only {available} FLCs available for Dispatch #{parent.id}!", "warning")
                        continue

                    new_dispatch = DispatchData(
                        from_user_id=user.id,
                        to_end_user_id=end_user_id,
                        dispatch_type="filled",
                        parent_dispatch_id=parent.id,
                        from_role="Intermediate",
                        to_role="End User",
                        component=parent.component,
                        flc_qty=flc_qty,
                        component_qty=comp_qty,
                        status="Delivered",
                        remarks=remarks,
                        date_time=datetime.utcnow()
                    )
                    db.session.add(new_dispatch)

                    if available - flc_qty == 0:
                        parent.status = "Processed"

            db.session.commit()
            flash("✅ Multiple FLCs dispatched to multiple End Users successfully!", "success")
            return redirect(url_for('dashboard'))


    # ---------- GET ----------
    if role == 'Supplier':
        intermediates = User.query.filter_by(role="Intermediate").all()
        return render_template('dispatch_create.html', role=role, users=intermediates, components=components)

    elif role == 'Intermediate':
        end_users = EndUser.query.order_by(EndUser.name.asc()).all()
        received_dispatches = DispatchData.query.filter(
            DispatchData.to_user_id == user.id,
            DispatchData.status.in_(["Received", "Processed"])
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
    current_user_id = session.get("user_id")
    current_user = User.query.get(current_user_id)

    if not current_user or current_user.role != 'Supplier':
        flash("Only suppliers can record returns.", "danger")
        return redirect(url_for('dashboard'))

    # GET REQUEST - Show available dispatches for return
    if request.method == 'GET':
        try:
            # Get all dispatches to end users first
            all_end_user_dispatches = db.session.query(
                DispatchData
            ).filter(
                DispatchData.dispatch_type == "filled",
                DispatchData.to_role == "End User",
                DispatchData.status.in_(["Delivered", "Received", "Partially Returned"])
            ).order_by(DispatchData.date_time.desc()).all()

            # Calculate remaining FLCs for each dispatch and filter
            dispatches_for_return = []
            for dispatch in all_end_user_dispatches:
                # Calculate returned quantity for this specific dispatch
                total_returned = db.session.query(
                    func.coalesce(func.sum(Returned.flc_qty), 0)
                ).filter(
                    Returned.dispatch_id == dispatch.id
                ).scalar() or 0

                remaining_flcs = dispatch.flc_qty - total_returned

                # Only include dispatches with remaining FLCs
                if remaining_flcs > 0:
                    # Get end user details
                    end_user = EndUser.query.get(dispatch.to_end_user_id) if dispatch.to_end_user_id else None
                    
                    dispatches_for_return.append({
                        'id': dispatch.id,
                        'component': dispatch.component,
                        'flc_qty': dispatch.flc_qty,
                        'remaining': remaining_flcs,
                        'total_returned': total_returned,
                        'end_user_name': end_user.name if end_user else 'Unknown',
                        'end_user_location': end_user.location if end_user else '',
                        'date_time': dispatch.date_time,
                        'to_end_user_id': dispatch.to_end_user_id
                    })

            # Get all end users for dropdown
            end_users = EndUser.query.order_by(EndUser.name.asc()).all()

            # Show recent returns for reference - FIXED: No relationship loading needed
            all_returns = Returned.query.order_by(Returned.date_time.desc()).limit(50).all()

            # We'll manually get dispatch and end user details for the template
            returns_with_details = []
            for return_item in all_returns:
                dispatch = DispatchData.query.get(return_item.dispatch_id)
                end_user = EndUser.query.get(return_item.from_end_user_id) if return_item.from_end_user_id else None
                
                returns_with_details.append({
                    'id': return_item.id,
                    'dispatch_id': return_item.dispatch_id,
                    'component': dispatch.component if dispatch else 'Unknown',
                    'from_end_user': end_user,
                    'flc_qty': return_item.flc_qty,
                    'remarks': return_item.remarks,
                    'date_time': return_item.date_time
                })

            return render_template('returns.html', 
                                 dispatches=dispatches_for_return, 
                                 returns=returns_with_details,
                                 end_users=end_users)

        except Exception as e:
            app.logger.error(f"Error in returns GET: {str(e)}")
            flash("Error loading return page. Please try again.", "danger")
            return redirect(url_for('dashboard'))

    # POST REQUEST - Handle return submission
    if request.method == 'POST':
        try:
            # Get the SPECIFIC dispatch that's being returned
            dispatch_id = int(request.form.get('dispatch_id', 0))
            flc_qty = int(request.form.get('flc_qty', 0))
            from_end_user_id = request.form.get('from_end_user_id')
            remarks = request.form.get('remarks', '').strip()

            # Get the specific dispatch
            dispatch = DispatchData.query.get(dispatch_id)
            if not dispatch:
                flash("Invalid dispatch selected.", "danger")
                return redirect(url_for('returns'))

            # Validate end user if provided
            if from_end_user_id:
                from_end_user = EndUser.query.get(int(from_end_user_id))
                if not from_end_user:
                    flash("Invalid end user selected.", "danger")
                    return redirect(url_for('returns'))
                
                # Verify the end user matches the dispatch
                if from_end_user.id != dispatch.to_end_user_id:
                    end_user_name = from_end_user.name if from_end_user else 'another end user'
                    flash(f"Error: This dispatch was sent to a different end user. Please select the correct end user.", "danger")
                    return redirect(url_for('returns'))

            # Calculate already returned quantity for THIS SPECIFIC DISPATCH
            total_returned_for_this_dispatch = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).filter(
                Returned.dispatch_id == dispatch_id
            ).scalar() or 0

            remaining_from_this_dispatch = dispatch.flc_qty - total_returned_for_this_dispatch

            # Validation
            if remaining_from_this_dispatch <= 0:
                flash("All FLCs from this dispatch have already been returned.", "info")
                return redirect(url_for('returns'))

            if flc_qty <= 0:
                flash("Returned quantity must be positive.", "warning")
                return redirect(url_for('returns'))

            if flc_qty > remaining_from_this_dispatch:
                flash(f"Cannot return {flc_qty} FLCs — only {remaining_from_this_dispatch} remaining from dispatch #{dispatch.id}.", "danger")
                return redirect(url_for('returns'))

            # Record the return for THIS SPECIFIC DISPATCH
            new_return = Returned(
                dispatch_id=dispatch.id,
                from_user_id=current_user.id,
                to_user_id=dispatch.from_user_id,
                from_end_user_id=dispatch.to_end_user_id,
                flc_qty=flc_qty,
                remarks=remarks,
                date_time=datetime.utcnow()
            )
            db.session.add(new_return)

            # Update dispatch status
            total_after_this_return = total_returned_for_this_dispatch + flc_qty
            if total_after_this_return >= dispatch.flc_qty:
                dispatch.status = "Returned"
            elif total_after_this_return > 0:
                dispatch.status = "Partially Returned"

            db.session.commit()
            
            # Get end user name for success message
            end_user = EndUser.query.get(dispatch.to_end_user_id) if dispatch.to_end_user_id else None
            end_user_name = end_user.name if end_user else "End User"
            flash(f"✅ Return of {flc_qty} FLCs from {end_user_name} recorded successfully for dispatch #{dispatch.id}.", "success")
            return redirect(url_for('returns'))

        except ValueError as e:
            flash("Invalid input data. Please check the form values.", "danger")
            return redirect(url_for('returns'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception("Error recording return")
            flash(f"Failed to record return: {str(e)}", "danger")
            return redirect(url_for('returns'))

# ------------------- COMPONENTS (Supplier manages) -------------------
# ------------------- MANAGE INTERMEDIATES -------------------
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def manage_users():
    """Supplier manages only Intermediate users."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Username and Password required!', 'danger')
            return redirect(url_for('manage_users'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'warning')
            return redirect(url_for('manage_users'))

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed, role='Intermediate')
        db.session.add(new_user)
        db.session.commit()
        flash(f"✅ Intermediate '{username}' added successfully.", 'success')
        return redirect(url_for('manage_users'))

    intermediates = User.query.filter_by(role='Intermediate').order_by(User.username).all()
    return render_template('manage_users.html', intermediates=intermediates)



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
    Safely delete a non-Supplier user and handle related dependencies.
    """
    user = User.query.get(user_id)
    if not user:
        flash('⚠️ User not found.', 'warning')
        return redirect(url_for('manage_users'))

    if user.role == 'Supplier':
        flash('❌ Cannot delete Supplier account.', 'danger')
        return redirect(url_for('manage_users'))

    try:
        # Clean related records before deletion
        DispatchData.query.filter(
            (DispatchData.from_user_id == user.id) | 
            (DispatchData.to_user_id == user.id)
        ).delete(synchronize_session=False)

        Returned.query.filter(
            (Returned.from_user_id == user.id) | 
            (Returned.to_user_id == user.id)
        ).delete(synchronize_session=False)

        InventoryConfig.query.filter_by(supplier_id=user.id).delete(synchronize_session=False)

        Component.query.filter_by(created_by=user.id).delete(synchronize_session=False)

        # Finally delete the user
        db.session.delete(user)
        db.session.commit()

        flash('✅ User deleted successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'❗ Error deleting user: {str(e)}', 'danger')

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

    if role == "Supplier":
        # --- Supplier Dispatches (A → B / C) ---
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
                "from_user": d.sender.username if d.sender else "Supplier",
                "to_user": d.receiver.username if d.receiver else d.to_role or "-",
                "component": d.component or "N/A",
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": returned_qty,
                "pending_qty": pending_qty,
                "status": d.status or "Pending",
                "date_time": d.date_time
            })

            if pending_qty > 0:
                pending_returns.append({
                    "id": d.id,
                    "from_user": d.sender.username if d.sender else "Supplier",
                    "to_user": d.receiver.username if d.receiver else d.to_role or "-",
                    "flc_qty": d.flc_qty or 0,
                    "returned_qty": returned_qty,
                    "pending_qty": pending_qty
                })

            if d.remarks:
                remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})

    elif role == "Intermediate":
        # --- Intermediate Dispatches & Receipts ---
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
                "from_user": d.sender.username if d.sender else "Supplier",
                "to_user": d.receiver.username if d.receiver else d.to_role or "End User",
                "component": d.component or "N/A",
                "flc_qty": d.flc_qty or 0,
                "returned_qty": 0,
                "pending_qty": 0,
                "status": d.status or "Pending",
                "date_time": d.date_time
            })

            if d.remarks:
                remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})

    else:
        # --- Admin (Full Overview) ---
        all_dispatches = DispatchData.query.order_by(DispatchData.id.desc()).all()
        for d in all_dispatches:
            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "Unknown",
                "to_user": d.receiver.username if d.receiver else d.to_role or "Unknown",
                "component": d.component or "N/A",
                "flc_qty": d.flc_qty or 0,
                "returned_qty": 0,
                "pending_qty": 0,
                "status": d.status or "Pending",
                "date_time": d.date_time
            })

    # ✅ Render final report without separate "returns"
    return render_template(
        "reports.html",
        cycle_report=cycle_report,
        pending_returns=pending_returns,
        remarks=remarks_list,
        role=role
    )






# ------------------- COMPONENT MANAGEMENT (Supplier Only) -------------------
# ------------------- VIEW COMPONENTS -------------------
@app.route('/components')
@login_required
@role_required('Supplier')
def components():
    comps = Component.query.order_by(Component.created_at.desc()).all()
    return render_template("components.html", components=comps)


# ------------------- ADD COMPONENT -------------------
@app.route('/add_component', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def add_component():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        stock_qty = request.form.get('stock_qty', 0, type=int)

        if not name:
            flash("Component name required!", "danger")
            return redirect(url_for('add_component'))

        if Component.query.filter_by(name=name).first():
            flash("Component with this name already exists!", "warning")
            return redirect(url_for('add_component'))

        comp = Component(
            name=name,
            description=description,
            flc_stock=stock_qty,
            created_by=session.get("user_id")
        )
        db.session.add(comp)
        db.session.commit()

        flash(f"✅ Component '{name}' added successfully with {stock_qty} FLCs!", "success")
        return redirect(url_for('components'))

    return render_template("add_component.html")



# ------------------- EDIT COMPONENT -------------------
@app.route('/edit_component/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def edit_component(id):
    component = Component.query.get_or_404(id)

    if request.method == 'POST':
        component.name = request.form.get('name', '').strip()
        component.description = request.form.get('description', '').strip()
        component.flc_stock = request.form.get('flc_stock', component.flc_stock, type=int)

        db.session.commit()
        flash(f"✅ Component '{component.name}' updated successfully with {component.flc_stock} FLCs!", "success")
        return redirect(url_for('components'))

    return render_template("edit_component.html", component=component)


# ------------------- DELETE COMPONENT -------------------
@app.route('/delete_component/<int:component_id>', methods=['POST'])
@login_required
def delete_component(component_id):
    component = Component.query.get_or_404(component_id)
    db.session.delete(component)
    db.session.commit()
    flash('✅ Component deleted successfully.', 'success')
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
@app.route("/reports/analytics")
@login_required
@role_required("Supplier")
def supplier_analytics():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash("Session expired or user not found. Please log in again.", "danger")
        return redirect(url_for("logout"))

    # === REAL-TIME SUPPLIER INVENTORY CALCULATION ===
    def get_realtime_supplier_inventory():
        """Get real-time supplier inventory with component breakdown"""
        supplier_id = session.get('user_id')
        inventory_data = {
            'total_available': 0,
            'components': [],
            'dispatched_today': 0,
            'returned_today': 0
        }
        
        today = datetime.utcnow().date()
        
        # Calculate for each component
        components = Component.query.filter_by(created_by=supplier_id).all()
        
        for component in components:
            # Total dispatched for this component
            total_dispatched = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.from_user_id == supplier_id,
                DispatchData.component == component.name,
                DispatchData.dispatch_type == 'empty'
            ).scalar() or 0
            
            # Total returned for this component
            total_returned = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).join(DispatchData, Returned.dispatch_id == DispatchData.id
            ).filter(
                Returned.to_user_id == supplier_id,
                DispatchData.component == component.name
            ).scalar() or 0
            
            # Today's dispatches
            dispatched_today = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.from_user_id == supplier_id,
                DispatchData.component == component.name,
                DispatchData.dispatch_type == 'empty',
                func.date(DispatchData.date_time) == today
            ).scalar() or 0
            
            # Today's returns
            returned_today = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).join(DispatchData, Returned.dispatch_id == DispatchData.id
            ).filter(
                Returned.to_user_id == supplier_id,
                DispatchData.component == component.name,
                func.date(Returned.date_time) == today
            ).scalar() or 0
            
            available = component.flc_stock - total_dispatched + total_returned
            
            inventory_data['components'].append({
                'name': component.name,
                'baseline_stock': component.flc_stock,
                'dispatched': total_dispatched,
                'returned': total_returned,
                'available': max(available, 0),
                'dispatched_today': dispatched_today,
                'returned_today': returned_today
            })
            
            inventory_data['total_available'] += max(available, 0)
            inventory_data['dispatched_today'] += dispatched_today
            inventory_data['returned_today'] += returned_today
        
        return inventory_data

    # Get real-time inventory
    realtime_inventory = get_realtime_supplier_inventory()

    # === COMPONENT-BASED FLC CALCULATIONS ===
    components = Component.query.all()
    component_analytics = {}
    
    for component in components:
        # Total FLCs sent for this component (to intermediates)
        total_sent_empty = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.from_user_id == user.id,
            DispatchData.dispatch_type == "empty",
            DispatchData.to_role == "Intermediate",
            DispatchData.component == component.name
        ).scalar() or 0

        # Total returns received for this component
        total_returns_received = db.session.query(
            func.coalesce(func.sum(Returned.flc_qty), 0)
        ).join(DispatchData, Returned.dispatch_id == DispatchData.id)\
         .filter(
            Returned.to_user_id == user.id,
            DispatchData.component == component.name
        ).scalar() or 0

        # Total filled FLCs delivered to end users for this component
        total_filled_to_endusers = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.dispatch_type == "filled",
            DispatchData.to_role == "End User",
            DispatchData.component == component.name,
            DispatchData.status.in_(["Delivered", "Received"])
        ).scalar() or 0

        # Calculate current distribution for this component
        flc_at_supplier = component.flc_stock - total_sent_empty + total_returns_received
        flc_at_intermediate = total_sent_empty - total_filled_to_endusers
        flc_at_enduser = total_filled_to_endusers - total_returns_received

        # Ensure non-negative
        flc_at_supplier = max(flc_at_supplier, 0)
        flc_at_intermediate = max(flc_at_intermediate, 0)
        flc_at_enduser = max(flc_at_enduser, 0)

        # Calculate utilization rate with zero division protection
        utilization_rate = 0
        if component.flc_stock > 0:
            utilization_rate = round(((total_sent_empty - total_returns_received) / component.flc_stock * 100), 1)

        component_analytics[component.name] = {
            'component_id': component.id,
            'baseline_stock': component.flc_stock,
            'at_supplier': flc_at_supplier,
            'at_intermediate': flc_at_intermediate,
            'at_enduser': flc_at_enduser,
            'total_sent': total_sent_empty,
            'total_returned': total_returns_received,
            'total_delivered': total_filled_to_endusers,
            'utilization_rate': utilization_rate
        }

    # === AGGREGATE TOTALS ACROSS ALL COMPONENTS ===
    total_at_supplier = sum(comp['at_supplier'] for comp in component_analytics.values())
    total_at_intermediate = sum(comp['at_intermediate'] for comp in component_analytics.values())
    total_at_enduser = sum(comp['at_enduser'] for comp in component_analytics.values())
    total_baseline = sum(comp['baseline_stock'] for comp in component_analytics.values())
    total_sent = sum(comp['total_sent'] for comp in component_analytics.values())
    total_returned = sum(comp['total_returned'] for comp in component_analytics.values())
    total_delivered = sum(comp['total_delivered'] for comp in component_analytics.values())

    # Calculate overall utilization rate with zero division protection
    overall_utilization_rate = 0
    if total_baseline > 0:
        overall_utilization_rate = round(((total_sent - total_returned) / total_baseline * 100), 1)

    # === BUSINESS METRICS ===
    total_dispatches = DispatchData.query.filter_by(from_user_id=user.id).count()
    completed_dispatches = DispatchData.query.filter_by(from_user_id=user.id, status="Received").count()
    dispatch_efficiency = (completed_dispatches / total_dispatches * 100) if total_dispatches > 0 else 0
    return_rate = (total_returned / total_sent * 100) if total_sent > 0 else 0

    # Component utilization data for charts
    component_usage = []
    for comp_name, analytics in component_analytics.items():
        component_usage.append({
            'component': comp_name,
            'flcs': analytics['total_sent'],
            'components': analytics['total_delivered'],
            'utilization': analytics['utilization_rate']
        })

    # Intermediate Performance
    intermediate_performance = db.session.query(
        User.username,
        DispatchData.component,
        func.count(DispatchData.id).label('dispatch_count'),
        func.sum(DispatchData.flc_qty).label('total_flcs'),
    ).join(DispatchData, User.id == DispatchData.to_user_id)\
     .filter(
        DispatchData.from_user_id == user.id,
        User.role == "Intermediate"
    ).group_by(User.id, User.username, DispatchData.component).all()

    # Calculate turnaround times
    turnaround_data = {}
    for perf in intermediate_performance:
        username, component, dispatch_count, total_flcs = perf
        intermediate_user = User.query.filter_by(username=username).first()
        
        if intermediate_user:
            first_last = db.session.query(
                func.min(DispatchData.date_time).label('first_dispatch'),
                func.max(DispatchData.date_time).label('last_dispatch'),
                func.count(DispatchData.id).label('total_dispatches')
            ).filter(
                DispatchData.to_user_id == intermediate_user.id,
                DispatchData.from_user_id == user.id,
                DispatchData.component == component
            ).first()
            
            if first_last and first_last.total_dispatches > 1:
                days_diff = (first_last.last_dispatch - first_last.first_dispatch).days
                avg_turnaround = days_diff / (first_last.total_dispatches - 1) if first_last.total_dispatches > 1 else 0
            else:
                avg_turnaround = 0
            
            key = f"{username}_{component}"
            turnaround_data[key] = round(avg_turnaround, 1)

    # Enhanced intermediate performance
    enhanced_performance = []
    for perf in intermediate_performance:
        username, component, dispatch_count, total_flcs = perf
        key = f"{username}_{component}"
        
        enhanced_performance.append({
            'name': username,
            'component': component,
            'dispatches': dispatch_count,
            'flcs': total_flcs or 0,
            'turnaround': turnaround_data.get(key, 0)
        })

    # === USER-WISE FLC DISTRIBUTION ===
    def calculate_current_flc_distribution():
        """Calculate exactly how many FLCs each user currently holds"""
        
        # Get intermediates with current FLC counts
        intermediates_with_flcs = []
        intermediate_users = User.query.filter_by(role='Intermediate').all()
        
        for user in intermediate_users:
            # Calculate FLCs currently with this intermediate
            received_flcs = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.to_user_id == user.id,
                DispatchData.dispatch_type == 'empty',
                DispatchData.status.in_(['Received', 'Pending'])
            ).scalar() or 0
            
            # Subtract FLCs already dispatched to end users
            dispatched_flcs = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.from_user_id == user.id,
                DispatchData.dispatch_type == 'filled'
            ).scalar() or 0
            
            current_flcs = received_flcs - dispatched_flcs
            
            if current_flcs > 0:
                # Get components for this intermediate
                components = db.session.query(
                    DispatchData.component,
                    func.sum(DispatchData.flc_qty).label('total_flcs')
                ).filter(
                    DispatchData.to_user_id == user.id,
                    DispatchData.status.in_(['Received', 'Pending'])
                ).group_by(DispatchData.component).all()
                
                intermediates_with_flcs.append({
                    'id': user.id,
                    'username': user.username,
                    'total_flcs': current_flcs,
                    'components': [{'name': comp[0], 'flcs': comp[1]} for comp in components],
                    'avg_holding_days': 0,  # Simplified for this example
                    'created_at': user.created_at
                })
        
        # Get end users with current FLC counts
        end_users_with_flcs = []
        all_end_users = EndUser.query.all()
        
        for end_user in all_end_users:
            # Calculate FLCs currently with this end user
            received_flcs = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.to_end_user_id == end_user.id,
                DispatchData.dispatch_type == 'filled',
                DispatchData.status.in_(['Delivered', 'Received'])
            ).scalar() or 0
            
            # Subtract returned FLCs
            returned_flcs = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).filter(
                Returned.from_end_user_id == end_user.id
            ).scalar() or 0
            
            current_flcs = received_flcs - returned_flcs
            
            if current_flcs > 0:
                # Get components for this end user
                components = db.session.query(
                    DispatchData.component,
                    func.sum(DispatchData.flc_qty).label('total_flcs')
                ).filter(
                    DispatchData.to_end_user_id == end_user.id,
                    DispatchData.status.in_(['Delivered', 'Received'])
                ).group_by(DispatchData.component).all()
                
                end_users_with_flcs.append({
                    'id': end_user.id,
                    'name': end_user.name,
                    'location': end_user.location,
                    'total_flcs': current_flcs,
                    'components': [{'name': comp[0], 'flcs': comp[1]} for comp in components],
                    'holding_since': '2024-01-01',  # Simplified
                    'days_remaining': 30  # Simplified
                })
        
        return {
            'intermediates': intermediates_with_flcs,
            'end_users': end_users_with_flcs,
            'total_flcs_at_supplier': realtime_inventory['total_available'],  # Use real-time data
            'total_flcs_with_intermediates': sum(u['total_flcs'] for u in intermediates_with_flcs),
            'total_flcs_with_endusers': sum(u['total_flcs'] for u in end_users_with_flcs),
            'total_flcs_in_system': total_baseline,
            'total_users': len(intermediates_with_flcs) + len(end_users_with_flcs)
        }

    user_distribution = calculate_current_flc_distribution()

    # === TIME-SERIES DATA FOR CHARTS ===
    today = datetime.utcnow().date()
    dates = []
    dispatch_counts = []
    return_counts = []
    flc_movement = []

    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        dates.append(day.strftime("%m/%d"))
        
        day_dispatch = DispatchData.query.filter(
            DispatchData.from_user_id == user.id,
            func.date(DispatchData.date_time) == day
        ).count()
        dispatch_counts.append(day_dispatch)
        
        day_returns = Returned.query.filter(
            Returned.to_user_id == user.id,
            func.date(Returned.date_time) == day
        ).count()
        return_counts.append(day_returns)
        
        day_flc_sent = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
            DispatchData.from_user_id == user.id,
            func.date(DispatchData.date_time) == day
        ).scalar() or 0
        
        day_flc_returned = db.session.query(func.coalesce(func.sum(Returned.flc_qty), 0)).filter(
            Returned.to_user_id == user.id,
            func.date(Returned.date_time) == day
        ).scalar() or 0
        
        flc_movement.append(day_flc_sent - day_flc_returned)

    # Returns by End User
    returns_by_end_user = db.session.query(
        EndUser.name,
        EndUser.location,
        func.sum(Returned.flc_qty).label('total_returns')
    ).join(Returned, Returned.from_end_user_id == EndUser.id)\
     .filter(Returned.to_user_id == user.id)\
     .group_by(EndUser.id, EndUser.name, EndUser.location)\
     .order_by(func.sum(Returned.flc_qty).desc())\
     .all()

    # === PREPARE DATA FOR TEMPLATE ===
    flc_summary = {
        "at_supplier": realtime_inventory['total_available'],  # Use real-time data
        "at_intermediate": total_at_intermediate,
        "at_enduser": total_at_enduser,
        "total_sent": total_sent,
        "total_returned": total_returned,
        "total_delivered": total_delivered,
        "baseline": total_baseline,
        "efficiency": round(dispatch_efficiency, 1),
        "return_rate": round(return_rate, 1),
        "utilization_rate": overall_utilization_rate,
        "total_components": len(components),
    }

    chart_data = {
        "dates": dates,
        "dispatch_trend": dispatch_counts,
        "return_trend": return_counts,
        "flc_movement": flc_movement,
        "component_usage": {
            "components": [c['component'] for c in component_usage],
            "utilization": [c['utilization'] for c in component_usage],
            "flcs": [c['flcs'] for c in component_usage]
        }
    }

    stats = {
        "total_dispatches": total_dispatches,
        "pending": DispatchData.query.filter_by(from_user_id=user.id, status="Pending").count(),
        "received": completed_dispatches,
        "returned": Returned.query.filter_by(to_user_id=user.id).count(),
        "efficiency": round(dispatch_efficiency, 1),
        "return_rate": round(return_rate, 1),
        "total_components": len(components),
        "active_components": len([c for c in component_analytics.values() if c['total_sent'] > 0])
    }

    return render_template(
        "supplier_analytics.html",
        stats=stats,
        chart_data=json.dumps(chart_data),
        flc_summary=flc_summary,
        component_usage=component_usage,
        intermediate_performance=enhanced_performance,
        component_analytics=component_analytics,
        intermediate_users=user_distribution['intermediates'],
        end_users=user_distribution['end_users'],
        total_flcs_at_supplier=realtime_inventory['total_available'],
        total_flcs_with_intermediates=user_distribution['total_flcs_with_intermediates'],
        total_flcs_with_endusers=user_distribution['total_flcs_with_endusers'],
        total_flcs_in_system=user_distribution['total_flcs_in_system'],
        total_users=user_distribution['total_users'],
        returns_by_end_user=returns_by_end_user,
        realtime_inventory=realtime_inventory
    )

@app.route("/api/realtime/inventory")
@login_required
@role_required("Supplier")
def api_realtime_inventory():
    """API endpoint for real-time inventory data"""
    def get_realtime_supplier_inventory():
        supplier_id = session.get('user_id')
        inventory_data = {
            'total_available': 0,
            'components': [],
            'dispatched_today': 0,
            'returned_today': 0
        }
        
        today = datetime.utcnow().date()
        components = Component.query.filter_by(created_by=supplier_id).all()
        
        for component in components:
            total_dispatched = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.from_user_id == supplier_id,
                DispatchData.component == component.name,
                DispatchData.dispatch_type == 'empty'
            ).scalar() or 0
            
            total_returned = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).join(DispatchData, Returned.dispatch_id == DispatchData.id
            ).filter(
                Returned.to_user_id == supplier_id,
                DispatchData.component == component.name
            ).scalar() or 0
            
            dispatched_today = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.from_user_id == supplier_id,
                DispatchData.component == component.name,
                DispatchData.dispatch_type == 'empty',
                func.date(DispatchData.date_time) == today
            ).scalar() or 0
            
            returned_today = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).join(DispatchData, Returned.dispatch_id == DispatchData.id
            ).filter(
                Returned.to_user_id == supplier_id,
                DispatchData.component == component.name,
                func.date(Returned.date_time) == today
            ).scalar() or 0
            
            available = component.flc_stock - total_dispatched + total_returned
            
            inventory_data['components'].append({
                'name': component.name,
                'baseline_stock': component.flc_stock,
                'dispatched': total_dispatched,
                'returned': total_returned,
                'available': max(available, 0),
                'dispatched_today': dispatched_today,
                'returned_today': returned_today
            })
            
            inventory_data['total_available'] += max(available, 0)
            inventory_data['dispatched_today'] += dispatched_today
            inventory_data['returned_today'] += returned_today
        
        return inventory_data
    
    return jsonify(get_realtime_supplier_inventory())


def get_end_user_holdings():
    end_users_data = []
    
    for end_user in EndUser.query.all():
        # Get ALL deliveries to this end user with their specific IDs
        deliveries = db.session.query(
            DispatchData.id,
            DispatchData.component,
            DispatchData.flc_qty
        ).filter(
            DispatchData.to_end_user_id == end_user.id,
            DispatchData.dispatch_type == 'filled'
        ).all()
        
        # Get ALL returns with their specific dispatch IDs
        returns = db.session.query(
            Returned.dispatch_id,
            Returned.flc_qty
        ).filter(
            Returned.from_end_user_id == end_user.id
        ).all()
        
        # Group returns by dispatch_id
        returns_by_dispatch = {}
        for dispatch_id, returned_qty in returns:
            returns_by_dispatch[dispatch_id] = returns_by_dispatch.get(dispatch_id, 0) + returned_qty
        
        # Calculate current holdings per component
        component_holdings = {}
        
        for dispatch_id, component, delivered_qty in deliveries:
            returned_qty = returns_by_dispatch.get(dispatch_id, 0)
            current_for_this_dispatch = delivered_qty - returned_qty
            
            if current_for_this_dispatch > 0:
                if component not in component_holdings:
                    component_holdings[component] = 0
                component_holdings[component] += current_for_this_dispatch
        
        # Convert to the format needed for display
        user_components = []
        total_flcs = 0
        
        for component, current_qty in component_holdings.items():
            if current_qty > 0:
                user_components.append({
                    'name': component,
                    'flcs': current_qty
                })
                total_flcs += current_qty
        
        if total_flcs > 0:
            end_users_data.append({
                'id': end_user.id,
                'name': end_user.name,
                'location': end_user.location or 'N/A',
                'total_flcs': total_flcs,
                'components': user_components
            })
    
    return end_users_data



def calculate_current_flc_distribution():
    """Calculate exactly how many FLCs each user currently holds WITH COMPONENT BREAKDOWN"""
    
    # Get intermediates with current FLC counts
    intermediates_with_flcs = []
    intermediate_users = User.query.filter_by(role='Intermediate').all()
    
    for user in intermediate_users:
        # Calculate FLCs currently with this intermediate - COMPONENT WISE
        component_data = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('received_flcs')
        ).filter(
            DispatchData.to_user_id == user.id,
            DispatchData.dispatch_type == 'empty',
            DispatchData.status.in_(['Received', 'Pending'])
        ).group_by(DispatchData.component).all()
        
        dispatched_data = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('dispatched_flcs')
        ).filter(
            DispatchData.from_user_id == user.id,
            DispatchData.dispatch_type == 'filled'
        ).group_by(DispatchData.component).all()
        
        # Create dispatched dictionary for easy lookup
        dispatched_dict = {comp: flcs for comp, flcs in dispatched_data}
        
        user_components = []
        total_user_flcs = 0
        
        for component, received_flcs in component_data:
            dispatched_flcs = dispatched_dict.get(component, 0)
            current_flcs = received_flcs - dispatched_flcs
            
            if current_flcs > 0:
                user_components.append({
                    'name': component,
                    'flcs': current_flcs
                })
                total_user_flcs += current_flcs
        
        if total_user_flcs > 0:
            intermediates_with_flcs.append({
                'id': user.id,
                'username': user.username,
                'total_flcs': total_user_flcs,
                'components': user_components,
                'avg_holding_days': 0,
                'created_at': user.created_at
            })
    
    # Get end users with current FLC counts - COMPONENT WISE
    end_users_with_flcs = []
    all_end_users = EndUser.query.all()
    
    for end_user in all_end_users:
        # Calculate FLCs currently with this end user - COMPONENT WISE
        delivered_data = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('delivered_flcs')
        ).filter(
            DispatchData.to_end_user_id == end_user.id,
            DispatchData.dispatch_type == 'filled',
            DispatchData.status.in_(['Delivered', 'Received'])
        ).group_by(DispatchData.component).all()
        
        returned_data = db.session.query(
            DispatchData.component,
            func.sum(Returned.flc_qty).label('returned_flcs')
        ).join(DispatchData, Returned.dispatch_id == DispatchData.id
        ).filter(
            Returned.from_end_user_id == end_user.id
        ).group_by(DispatchData.component).all()
        
        # Create returned dictionary for easy lookup
        returned_dict = {comp: flcs for comp, flcs in returned_data}
        
        user_components = []
        total_user_flcs = 0
        
        for component, delivered_flcs in delivered_data:
            returned_flcs = returned_dict.get(component, 0)
            current_flcs = delivered_flcs - returned_flcs
            
            if current_flcs > 0:
                user_components.append({
                    'name': component,
                    'flcs': current_flcs
                })
                total_user_flcs += current_flcs
        
        if total_user_flcs > 0:
            # Get holding since date
            first_delivery = db.session.query(
                func.min(DispatchData.date_time)
            ).filter(
                DispatchData.to_end_user_id == end_user.id,
                DispatchData.dispatch_type == 'filled'
            ).scalar()
            
            holding_since = first_delivery.strftime('%Y-%m-%d') if first_delivery else '2024-01-01'
            
            end_users_with_flcs.append({
                'id': end_user.id,
                'name': end_user.name,
                'location': end_user.location,
                'total_flcs': total_user_flcs,
                'components': user_components,
                'holding_since': holding_since,
                'days_remaining': 30  # Simplified for now
            })
    
    return {
        'intermediates': intermediates_with_flcs,
        'end_users': end_users_with_flcs,
        'total_flcs_at_supplier': realtime_inventory['total_available'],
        'total_flcs_with_intermediates': sum(u['total_flcs'] for u in intermediates_with_flcs),
        'total_flcs_with_endusers': sum(u['total_flcs'] for u in end_users_with_flcs),
        'total_flcs_in_system': sum(comp.flc_stock for comp in Component.query.all()),
        'total_users': len(intermediates_with_flcs) + len(end_users_with_flcs)
    }

# Add these helper functions to your Flask app

def calculate_avg_holding_time(user_id):
    """Calculate average holding time for an intermediate user"""
    holding_times = db.session.query(
        func.avg(func.extract('epoch', func.now() - DispatchData.date_time) / 86400)
    ).filter(
        DispatchData.to_user_id == user_id,
        DispatchData.dispatch_type == 'empty',
        DispatchData.status.in_(['Received', 'Pending'])
    ).scalar() or 0
    
    return round(holding_times, 1)

def get_holding_since(end_user_id):
    """Get when an end user first received FLCs"""
    first_receipt = db.session.query(
        func.min(DispatchData.date_time)
    ).filter(
        DispatchData.to_end_user_id == end_user_id,
        DispatchData.dispatch_type == 'filled',
        DispatchData.status.in_(['Delivered', 'Received'])
    ).scalar()
    
    if first_receipt:
        return first_receipt.strftime('%Y-%m-%d')
    return 'N/A'

def calculate_return_due(end_user_id):
    """Calculate days remaining until return is due (simplified logic)"""
    # Simple implementation: assume 30-day cycle from first receipt
    first_receipt = db.session.query(
        func.min(DispatchData.date_time)
    ).filter(
        DispatchData.to_end_user_id == end_user_id,
        DispatchData.dispatch_type == 'filled'
    ).scalar()
    
    if first_receipt:
        days_held = (datetime.utcnow() - first_receipt).days
        days_remaining = 30 - days_held
        return days_remaining
    return 0

def calculate_supplier_stock():
    """Calculate REAL-TIME FLCs currently available at supplier"""
    supplier_id = session.get('user_id')
    
    # Get all components owned by this supplier
    supplier_components = Component.query.filter_by(created_by=supplier_id).all()
    
    total_available = 0
    
    for component in supplier_components:
        # Calculate FLCs dispatched for this component
        dispatched_flcs = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.from_user_id == supplier_id,
            DispatchData.component == component.name,
            DispatchData.dispatch_type == 'empty'
        ).scalar() or 0
        
        # Calculate FLCs returned for this component
        returned_flcs = db.session.query(
            func.coalesce(func.sum(Returned.flc_qty), 0)
        ).join(DispatchData, Returned.dispatch_id == DispatchData.id
        ).filter(
            Returned.to_user_id == supplier_id,
            DispatchData.component == component.name
        ).scalar() or 0
        
        # Real-time available = baseline stock - dispatched + returned
        component_available = component.flc_stock - dispatched_flcs + returned_flcs
        total_available += max(component_available, 0)  # Ensure non-negative
    
    return total_available

def calculate_total_system_flcs():
    """Calculate total FLCs in the entire system"""
    # Sum of all component baseline stocks
    total_baseline = db.session.query(
        func.coalesce(func.sum(Component.flc_stock), 0)
    ).scalar() or 0
    return total_baseline

def calculate_supplier_stock():
    """Calculate REAL-TIME FLCs currently available at supplier"""
    supplier_id = session.get('user_id')
    
    # Get all components owned by this supplier
    supplier_components = Component.query.filter_by(created_by=supplier_id).all()
    
    total_available = 0
    
    for component in supplier_components:
        # Calculate FLCs dispatched for this component
        dispatched_flcs = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.from_user_id == supplier_id,
            DispatchData.component == component.name,
            DispatchData.dispatch_type == 'empty'
        ).scalar() or 0
        
        # Calculate FLCs returned for this component
        returned_flcs = db.session.query(
            func.coalesce(func.sum(Returned.flc_qty), 0)
        ).join(DispatchData, Returned.dispatch_id == DispatchData.id
        ).filter(
            Returned.to_user_id == supplier_id,
            DispatchData.component == component.name
        ).scalar() or 0
        
        # Real-time available = baseline stock - dispatched + returned
        component_available = component.flc_stock - dispatched_flcs + returned_flcs
        total_available += max(component_available, 0)  # Ensure non-negative
    
    return total_available


def get_user_components(user_id, user_type):
    """Get component-wise breakdown for a user"""
    components = []
    
    if user_type == 'intermediate':
        # Components currently with intermediate (received but not yet dispatched)
        received_components = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('total_received')
        ).filter(
            DispatchData.to_user_id == user_id,
            DispatchData.dispatch_type == 'empty',
            DispatchData.status.in_(['Received', 'Pending'])
        ).group_by(DispatchData.component).all()
        
        dispatched_components = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('total_dispatched')
        ).filter(
            DispatchData.from_user_id == user_id,
            DispatchData.dispatch_type == 'filled'
        ).group_by(DispatchData.component).all()
        
        # Create a dictionary of dispatched quantities by component
        dispatched_dict = {comp[0]: comp[1] for comp in dispatched_components}
        
        # Calculate current holdings: received - dispatched
        for comp in received_components:
            component_name = comp[0]
            received_qty = comp[1] or 0
            dispatched_qty = dispatched_dict.get(component_name, 0)
            current_qty = received_qty - dispatched_qty
            
            if current_qty > 0:
                components.append({
                    'name': component_name,
                    'flcs': current_qty
                })
                
    else:  # end_user
        # Components currently with end user (delivered but not returned)
        delivered_components = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('total_delivered')
        ).filter(
            DispatchData.to_end_user_id == user_id,
            DispatchData.dispatch_type == 'filled',
            DispatchData.status.in_(['Delivered', 'Received'])
        ).group_by(DispatchData.component).all()
        
        returned_components = db.session.query(
            DispatchData.component,
            func.sum(Returned.flc_qty).label('total_returned')
        ).join(Returned, Returned.dispatch_id == DispatchData.id
        ).filter(
            Returned.from_end_user_id == user_id
        ).group_by(DispatchData.component).all()
        
        # Create a dictionary of returned quantities by component
        returned_dict = {comp[0]: comp[1] for comp in returned_components}
        
        # Calculate current holdings: delivered - returned
        for comp in delivered_components:
            component_name = comp[0]
            delivered_qty = comp[1] or 0
            returned_qty = returned_dict.get(component_name, 0)
            current_qty = delivered_qty - returned_qty
            
            if current_qty > 0:
                components.append({
                    'name': component_name,
                    'flcs': current_qty
                })
    
    return components

def calculate_current_flc_distribution():
    """Calculate exactly how many FLCs each user currently holds"""
    
    # Get intermediates with current FLC counts
    intermediates_with_flcs = []
    intermediate_users = User.query.filter_by(role='Intermediate').all()
    
    for user in intermediate_users:
        # Calculate FLCs currently with this intermediate
        received_flcs = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.to_user_id == user.id,
            DispatchData.dispatch_type == 'empty',
            DispatchData.status.in_(['Received', 'Pending'])
        ).scalar() or 0
        
        # Subtract FLCs already dispatched to end users
        dispatched_flcs = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.from_user_id == user.id,
            DispatchData.dispatch_type == 'filled'
        ).scalar() or 0
        
        current_flcs = received_flcs - dispatched_flcs
        
        if current_flcs > 0:
            intermediates_with_flcs.append({
                'id': user.id,
                'username': user.username,
                'total_flcs': current_flcs,
                'components': get_user_components(user.id, 'intermediate'),
                'avg_holding_days': calculate_avg_holding_time(user.id),
                'created_at': user.created_at
            })
    
    # Get end users with current FLC counts
    end_users_with_flcs = []
    all_end_users = EndUser.query.all()
    
    for user in all_end_users:
        # Calculate FLCs currently with this end user
        received_flcs = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.to_end_user_id == user.id,
            DispatchData.dispatch_type == 'filled',
            DispatchData.status.in_(['Delivered', 'Received'])
        ).scalar() or 0
        
        # Subtract returned FLCs
        returned_flcs = db.session.query(
            func.coalesce(func.sum(Returned.flc_qty), 0)
        ).filter(
            Returned.from_end_user_id == user.id
        ).scalar() or 0
        
        current_flcs = received_flcs - returned_flcs
        
        if current_flcs > 0:
            end_users_with_flcs.append({
                'id': user.id,
                'name': user.name,
                'location': user.location,
                'total_flcs': current_flcs,
                'components': get_user_components(user.id, 'end_user'),
                'holding_since': get_holding_since(user.id),
                'days_remaining': calculate_return_due(user.id)
            })
    
    return {
        'intermediates': intermediates_with_flcs,
        'end_users': end_users_with_flcs,
        'total_flcs_at_supplier': calculate_supplier_stock(),
        'total_flcs_with_intermediates': sum(u['total_flcs'] for u in intermediates_with_flcs),
        'total_flcs_with_endusers': sum(u['total_flcs'] for u in end_users_with_flcs),
        'total_flcs_in_system': calculate_total_system_flcs(),
        'total_users': len(intermediates_with_flcs) + len(end_users_with_flcs)
    }



def get_user_components(user_id, user_type):
    """Get component-wise breakdown for a user"""
    if user_type == 'intermediate':
        # Components currently with intermediate
        components = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('total_flcs')
        ).filter(
            DispatchData.to_user_id == user_id,
            DispatchData.status.in_(['Received', 'Pending'])
        ).group_by(DispatchData.component).all()
    else:
        # Components currently with end user
        components = db.session.query(
            DispatchData.component,
            func.sum(DispatchData.flc_qty).label('total_flcs')
        ).filter(
            DispatchData.to_end_user_id == user_id,
            DispatchData.status.in_(['Delivered', 'Received'])
        ).group_by(DispatchData.component).all()
    
    return [{'name': comp[0], 'flcs': comp[1]} for comp in components]



@app.before_request
def init_supplier_inventory():
    suppliers = User.query.filter_by(role="Supplier").all()
    for sup in suppliers:
        if not InventoryConfig.query.filter_by(supplier_id=sup.id).first():
            inv = InventoryConfig(supplier_id=sup.id, flc_stock=100)
            db.session.add(inv)
    db.session.commit()


@app.route("/api/user/<user_type>/<int:user_id>/details")
@login_required
@role_required("Supplier")
def api_user_details(user_type, user_id):
    """Get detailed information about a user's FLC holdings"""
    if user_type == 'intermediate':
        user = User.query.get_or_404(user_id)
        
        # Get detailed dispatch history
        dispatches = DispatchData.query.filter(
            DispatchData.to_user_id == user_id,
            DispatchData.dispatch_type == 'empty'
        ).order_by(DispatchData.date_time.desc()).limit(10).all()
        
        dispatch_history = []
        for dispatch in dispatches:
            dispatch_history.append({
                'id': dispatch.id,
                'component': dispatch.component,
                'flc_qty': dispatch.flc_qty,
                'status': dispatch.status,
                'date_time': dispatch.date_time.strftime('%Y-%m-%d %H:%M'),
                'from_user': dispatch.sender.username
            })
        
        return jsonify({
            'user_type': 'intermediate',
            'username': user.username,
            'total_current_flcs': calculate_current_intermediate_flcs(user_id),
            'dispatch_history': dispatch_history,
            'components': get_user_components(user_id, 'intermediate'),
            'performance_metrics': {
                'avg_holding_time': calculate_avg_holding_time(user_id),
                'total_dispatches_handled': DispatchData.query.filter_by(to_user_id=user_id).count(),
                'efficiency_rate': calculate_efficiency_rate(user_id)
            }
        })
    
    else:  # end_user
        user = EndUser.query.get_or_404(user_id)
        
        # Get delivery history
        deliveries = DispatchData.query.filter(
            DispatchData.to_end_user_id == user_id,
            DispatchData.dispatch_type == 'filled'
        ).order_by(DispatchData.date_time.desc()).limit(10).all()
        
        delivery_history = []
        for delivery in deliveries:
            delivery_history.append({
                'id': delivery.id,
                'component': delivery.component,
                'flc_qty': delivery.flc_qty,
                'status': delivery.status,
                'date_time': delivery.date_time.strftime('%Y-%m-%d %H:%M'),
                'from_intermediate': delivery.sender.username if delivery.sender else 'Unknown'
            })
        
        return jsonify({
            'user_type': 'end_user',
            'name': user.name,
            'location': user.location,
            'total_current_flcs': calculate_current_enduser_flcs(user_id),
            'delivery_history': delivery_history,
            'components': get_user_components(user_id, 'end_user'),
            'return_metrics': {
                'holding_since': get_holding_since(user_id),
                'days_remaining': calculate_return_due(user_id),
                'total_returns': Returned.query.filter_by(from_end_user_id=user_id).count()
            }
        })

def calculate_current_intermediate_flcs(user_id):
    """Calculate current FLCs for intermediate"""
    received = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
        DispatchData.to_user_id == user_id,
        DispatchData.dispatch_type == 'empty',
        DispatchData.status.in_(['Received', 'Pending'])
    ).scalar() or 0
    
    dispatched = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
        DispatchData.from_user_id == user_id,
        DispatchData.dispatch_type == 'filled'
    ).scalar() or 0
    
    return received - dispatched

def calculate_current_enduser_flcs(user_id):
    """Calculate current FLCs for end user"""
    delivered = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
        DispatchData.to_end_user_id == user_id,
        DispatchData.dispatch_type == 'filled',
        DispatchData.status.in_(['Delivered', 'Received'])
    ).scalar() or 0
    
    returned = db.session.query(func.coalesce(func.sum(Returned.flc_qty), 0)).filter(
        Returned.from_end_user_id == user_id
    ).scalar() or 0
    
    return delivered - returned

def calculate_efficiency_rate(user_id):
    """Calculate efficiency rate for intermediate"""
    total_received = DispatchData.query.filter_by(to_user_id=user_id).count()
    processed = DispatchData.query.filter_by(from_user_id=user_id).count()
    
    if total_received > 0:
        return round((processed / total_received) * 100, 1)
    return 0.0



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



# ------------------- MANAGE END USERS -------------------
@app.route('/manage_end_users', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def manage_end_users():
    """Supplier can add and view End Users."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location = request.form.get('location', '').strip()
        remarks = request.form.get('remarks', '').strip()

        if not name:
            flash("End User name is required.", "danger")
            return redirect(url_for('manage_end_users'))

        new_user = EndUser(name=name, location=location, remarks=remarks)
        db.session.add(new_user)
        db.session.commit()
        flash(f"✅ End User '{name}' added successfully.", "success")
        return redirect(url_for('manage_end_users'))

    end_users = EndUser.query.order_by(EndUser.created_at.desc()).all()
    return render_template('manage_end_users.html', end_users=end_users)


# ------------------- EDIT END USER -------------------
@app.route('/edit_end_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def edit_end_user(user_id):
    user = EndUser.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form.get('name', '').strip()
        user.location = request.form.get('location', '').strip()
        user.remarks = request.form.get('remarks', '').strip()
        db.session.commit()
        flash(f"✏️ End User '{user.name}' updated successfully.", "success")
        return redirect(url_for('manage_end_users'))
    return render_template('edit_end_user.html', user=user)


# ------------------- DELETE END USER -------------------
@app.route('/delete_end_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('Supplier')
def delete_end_user(user_id):
    user = EndUser.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"🗑️ End User '{user.name}' deleted successfully.", "success")
    return redirect(url_for('manage_end_users'))




# ------------------- DB INIT & RUN -------------------
if __name__ == "__main__":
    with app.app_context():
        
        db.create_all()
        
    app.run(debug=True)
