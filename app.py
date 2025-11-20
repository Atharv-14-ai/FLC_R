# app.py
from functools import wraps
import os
from datetime import datetime, timedelta  # Make sure timedelta is here
from collections import defaultdict
from sqlalchemy import cast, String
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
    # "postgresql://postgres:eKJOgGccJZtXKcUvrcEDkUteFbuzRsqh@switchback.proxy.rlwy.net:40253/railway"
    "postgresql://postgres:1234@localhost:5432/flc"
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


# Update the Returned model in app.py
class Returned(db.Model):
    __tablename__ = "returned"
    id = db.Column(db.Integer, primary_key=True)
    dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Intermediate
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)    # Supplier
    to_end_user_id = db.Column(db.Integer, db.ForeignKey('end_users.id'), nullable=True)  # NEW: Who returned it
    flc_qty = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])
    end_user = db.relationship('EndUser', foreign_keys=[to_end_user_id])  # NEW
    dispatch = db.relationship('DispatchData', foreign_keys=[dispatch_id])  # NEW

    def __repr__(self):
        return f"<Return {self.id} dispatch:{self.dispatch_id} from_end_user:{self.to_end_user_id} x{self.flc_qty}>"


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

    # ------------------ POST REQUEST: Record a Return ------------------
    if request.method == 'POST':
        try:
            dispatch_id = int(request.form.get('dispatch_id', 0))
            end_user_id = int(request.form.get('end_user_id', 0))  # NEW
            flc_qty = int(request.form.get('flc_qty', 0))
            remarks = request.form.get('remarks', '').strip()

            dispatch = DispatchData.query.get(dispatch_id)
            end_user = EndUser.query.get(end_user_id)  # NEW

            if not dispatch:
                flash("Invalid dispatch selected.", "danger")
                return redirect(url_for('returns'))
            
            if not end_user:  # NEW VALIDATION
                flash("Please select a valid end user.", "danger")
                return redirect(url_for('returns'))

            # Validate that this end user actually received FLCs from this dispatch
            end_user_dispatches = DispatchData.query.filter(
                DispatchData.parent_dispatch_id == dispatch_id,
                DispatchData.to_end_user_id == end_user_id
            ).all()
            
            if not end_user_dispatches:
                flash("Selected end user did not receive FLCs from this dispatch.", "danger")
                return redirect(url_for('returns'))

            # Calculate total FLCs sent to this end user from this dispatch
            total_sent_to_end_user = sum(d.flc_qty for d in end_user_dispatches)
            
            # Calculate already returned quantity from this end user for this dispatch
            total_returned_from_end_user = (
                db.session.query(db.func.coalesce(db.func.sum(Returned.flc_qty), 0))
                .filter(
                    Returned.dispatch_id == dispatch_id,
                    Returned.to_end_user_id == end_user_id
                )
                .scalar()
                or 0
            )
            
            remaining_from_end_user = total_sent_to_end_user - total_returned_from_end_user

            # Validation checks
            if remaining_from_end_user <= 0:
                flash(f"All FLCs from {end_user.name} for this dispatch have already been returned.", "info")
                return redirect(url_for('returns'))

            if flc_qty <= 0:
                flash("Returned quantity must be positive.", "warning")
                return redirect(url_for('returns'))

            if flc_qty > remaining_from_end_user:
                flash(f"Cannot return {flc_qty} FLCs — {end_user.name} only has {remaining_from_end_user} remaining from this dispatch.", "danger")
                return redirect(url_for('returns'))

            # Record the return WITH END USER
            new_return = Returned(
                dispatch_id=dispatch.id,
                from_user_id=current_user.id,  # supplier receiving return
                to_user_id=dispatch.from_user_id,  # intermediate who sent originally
                to_end_user_id=end_user_id,  # NEW: which end user returned
                flc_qty=flc_qty,
                remarks=remarks,
                date_time=datetime.utcnow()
            )
            db.session.add(new_return)

            # Update dispatch status based on overall returns
            total_returned_all = (
                db.session.query(db.func.coalesce(db.func.sum(Returned.flc_qty), 0))
                .filter_by(dispatch_id=dispatch_id)
                .scalar()
                or 0
            )
            
            if total_returned_all + flc_qty >= dispatch.flc_qty:
                dispatch.status = "Returned"
            elif total_returned_all + flc_qty > 0:
                dispatch.status = "Partially Returned"

            db.session.commit()
            flash(f"Return of {flc_qty} FLCs from {end_user.name} recorded successfully.", "success")
            return redirect(url_for('returns'))

        except Exception as e:
            db.session.rollback()
            app.logger.exception("Error recording return")
            flash(f"Failed to record return: {str(e)}", "danger")
            return redirect(url_for('returns'))

    # ------------------ GET REQUEST: Show Returns Page ------------------
    # Only include active dispatches that still have pending returns
    active_dispatches = (
        DispatchData.query.filter_by(from_user_id=current_user.id)
        .filter(DispatchData.status.in_(["Pending", "Partially Returned", "Received"]))
        .order_by(DispatchData.date_time.desc())
        .all()
    )

    dispatches = []
    for d in active_dispatches:
        total_returned = (
            db.session.query(db.func.coalesce(db.func.sum(Returned.flc_qty), 0))
            .filter_by(dispatch_id=d.id)
            .scalar()
            or 0
        )
        remaining = d.flc_qty - total_returned

        if remaining > 0:
            # Get end users who received FLCs from this dispatch
            end_users = db.session.query(EndUser).join(
                DispatchData, DispatchData.to_end_user_id == EndUser.id
            ).filter(
                DispatchData.parent_dispatch_id == d.id
            ).distinct().all()
            
            # Calculate remaining FLCs per end user
            end_user_data = []
            for eu in end_users:
                sent_to_end_user = db.session.query(
                    db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)
                ).filter(
                    DispatchData.parent_dispatch_id == d.id,
                    DispatchData.to_end_user_id == eu.id
                ).scalar() or 0
                
                returned_from_end_user = db.session.query(
                    db.func.coalesce(db.func.sum(Returned.flc_qty), 0)
                ).filter(
                    Returned.dispatch_id == d.id,
                    Returned.to_end_user_id == eu.id
                ).scalar() or 0
                
                remaining_end_user = sent_to_end_user - returned_from_end_user
                
                if remaining_end_user > 0:
                    end_user_data.append({
                        'id': eu.id,
                        'name': eu.name,
                        'location': eu.location,
                        'sent': sent_to_end_user,
                        'returned': returned_from_end_user,
                        'remaining': remaining_end_user
                    })
            
            d.total_returned = total_returned
            d.remaining = remaining
            d.end_users = end_user_data
            dispatches.append(d)

    # Show all returns with end user information
    all_returns = (
        Returned.query
        .options(db.joinedload(Returned.end_user))
        .options(db.joinedload(Returned.from_user))
        .order_by(Returned.date_time.desc())
        .limit(50)
        .all()
    )

    return render_template('returns.html', dispatches=dispatches, returns=all_returns)


# ------------------- NEW API ENDPOINT -------------------
@app.route('/api/dispatch/<int:dispatch_id>/endusers')
@login_required
def get_endusers_for_dispatch(dispatch_id):
    """Get end users who received FLCs from this dispatch and their remaining quantities"""
    current_user_id = session.get("user_id")
    
    # Verify the dispatch belongs to current user
    dispatch = DispatchData.query.filter_by(id=dispatch_id, from_user_id=current_user_id).first()
    if not dispatch:
        return jsonify([])
    
    end_users = db.session.query(EndUser).join(
        DispatchData, DispatchData.to_end_user_id == EndUser.id
    ).filter(
        DispatchData.parent_dispatch_id == dispatch_id
    ).distinct().all()
    
    result = []
    for eu in end_users:
        # Calculate remaining FLCs for this end user
        sent_to_end_user = db.session.query(
            db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.parent_dispatch_id == dispatch_id,
            DispatchData.to_end_user_id == eu.id
        ).scalar() or 0
        
        returned_from_end_user = db.session.query(
            db.func.coalesce(db.func.sum(Returned.flc_qty), 0)
        ).filter(
            Returned.dispatch_id == dispatch_id,
            Returned.to_end_user_id == eu.id
        ).scalar() or 0
        
        remaining = sent_to_end_user - returned_from_end_user
        
        if remaining > 0:
            result.append({
                'id': eu.id,
                'name': eu.name,
                'location': eu.location,
                'sent': sent_to_end_user,
                'returned': returned_from_end_user,
                'remaining': remaining
            })
    
    return jsonify(result)




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

    # === ACCURATE FLC CALCULATIONS (Using dispatch creation logic) ===
    
    # Get all dispatches sent by this supplier
    supplier_dispatches = DispatchData.query.filter_by(
        from_user_id=user.id, 
        dispatch_type="empty"
    ).all()

    # Calculate accurate FLC distribution
    total_baseline = db.session.query(func.coalesce(func.sum(Component.flc_stock), 0)).scalar() or 0
    
    # Calculate total sent FLCs
    total_sent = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
        DispatchData.from_user_id == user.id,
        DispatchData.dispatch_type == "empty"
    ).scalar() or 0

    # Calculate total returned FLCs
    total_returned = db.session.query(func.coalesce(func.sum(Returned.flc_qty), 0)).filter(
        Returned.to_user_id == user.id
    ).scalar() or 0

    # Calculate FLCs at supplier (using the same logic as inventory)
    flc_at_supplier = total_baseline - total_sent + total_returned

    # === ACCURATE INTERMEDIATE FLC CALCULATION ===
    intermediate_flc_data = {}
    
    for dispatch in supplier_dispatches:
        if dispatch.to_user_id not in intermediate_flc_data:
            intermediate_flc_data[dispatch.to_user_id] = {
                'username': dispatch.receiver.username if dispatch.receiver else 'Unknown',
                'components': {},
                'total_flcs': 0
            }
        
        # Calculate consumed FLCs for this dispatch (by end users)
        consumed = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
            DispatchData.parent_dispatch_id == dispatch.id
        ).scalar() or 0
        
        available = dispatch.flc_qty - consumed
        
        if dispatch.component not in intermediate_flc_data[dispatch.to_user_id]['components']:
            intermediate_flc_data[dispatch.to_user_id]['components'][dispatch.component] = 0
        
        intermediate_flc_data[dispatch.to_user_id]['components'][dispatch.component] += available
        intermediate_flc_data[dispatch.to_user_id]['total_flcs'] += available

    # Prepare intermediate distribution
    user_distribution = {'intermediates': [], 'end_users': []}
    
    for intermediate_id, data in intermediate_flc_data.items():
        if data['total_flcs'] > 0:  # Only show intermediates with available FLCs
            components_list = [{'name': comp, 'flcs': qty} for comp, qty in data['components'].items() if qty > 0]
            
            user_distribution['intermediates'].append({
                'username': data['username'],
                'role': 'Intermediate',
                'total_flcs': data['total_flcs'],
                'components': components_list
            })

    # === ACCURATE END USER FLC CALCULATION ===
    # Get all dispatches to end users
    end_user_dispatches = DispatchData.query.filter(
        DispatchData.dispatch_type == "filled",
        DispatchData.status.in_(["Delivered", "Received"])
    ).all()

    end_user_flc_data = {}
    
    for dispatch in end_user_dispatches:
        if dispatch.to_end_user_id not in end_user_flc_data:
            end_user = EndUser.query.get(dispatch.to_end_user_id)
            end_user_flc_data[dispatch.to_end_user_id] = {
                'name': end_user.name if end_user else 'Unknown',
                'location': end_user.location if end_user else '',
                'components': {},
                'total_flcs': 0,
                'intermediate': dispatch.sender.username if dispatch.sender else 'Unknown'
            }
        
        if dispatch.component not in end_user_flc_data[dispatch.to_end_user_id]['components']:
            end_user_flc_data[dispatch.to_end_user_id]['components'][dispatch.component] = 0
        
        # Calculate returned FLCs for this end user for this component
        returned_qty = db.session.query(func.coalesce(func.sum(Returned.flc_qty), 0)).filter(
            Returned.dispatch_id == dispatch.parent_dispatch_id,
            Returned.to_end_user_id == dispatch.to_end_user_id
        ).scalar() or 0
        
        net_flcs = dispatch.flc_qty - returned_qty
        
        if net_flcs > 0:
            end_user_flc_data[dispatch.to_end_user_id]['components'][dispatch.component] += net_flcs
            end_user_flc_data[dispatch.to_end_user_id]['total_flcs'] += net_flcs

    for end_user_id, data in end_user_flc_data.items():
        if data['total_flcs'] > 0:  # Only show end users with FLCs
            components_list = [{'name': comp, 'flcs': qty} for comp, qty in data['components'].items() if qty > 0]
            
            user_distribution['end_users'].append({
                'name': data['name'],
                'location': data['location'],
                'role': 'End User',
                'total_flcs': data['total_flcs'],
                'components': components_list,
                'intermediate': data['intermediate']
            })

    # Calculate FLCs in transit and with end users
    flc_at_intermediate = sum(user['total_flcs'] for user in user_distribution['intermediates'])
    flc_at_enduser = sum(user['total_flcs'] for user in user_distribution['end_users'])

    # === COMPONENT ANALYTICS ===
    components = Component.query.all()
    component_analytics = {}
    
    for component in components:
        # Calculate component-specific metrics
        component_sent = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
            DispatchData.from_user_id == user.id,
            DispatchData.dispatch_type == "empty",
            DispatchData.component == component.name
        ).scalar() or 0

        component_returned = db.session.query(func.coalesce(func.sum(Returned.flc_qty), 0)).join(
            DispatchData, Returned.dispatch_id == DispatchData.id
        ).filter(
            Returned.to_user_id == user.id,
            DispatchData.component == component.name
        ).scalar() or 0

        component_at_supplier = component.flc_stock - component_sent + component_returned
        
        # Calculate component at intermediate (using our accurate data)
        component_at_intermediate = 0
        for intermediate in user_distribution['intermediates']:
            for comp in intermediate['components']:
                if comp['name'] == component.name:
                    component_at_intermediate += comp['flcs']
        
        # Calculate component at end user (using our accurate data)
        component_at_enduser = 0
        for end_user in user_distribution['end_users']:
            for comp in end_user['components']:
                if comp['name'] == component.name:
                    component_at_enduser += comp['flcs']

        utilization_rate = 0
        if component.flc_stock > 0:
            utilization_rate = round(((component_sent - component_returned) / component.flc_stock * 100), 1)

        component_analytics[component.name] = {
            'component_id': component.id,
            'baseline_stock': component.flc_stock,
            'at_supplier': max(component_at_supplier, 0),
            'at_intermediate': component_at_intermediate,
            'at_enduser': component_at_enduser,
            'total_sent': component_sent,
            'total_returned': component_returned,
            'utilization_rate': utilization_rate
        }

    # === BUSINESS METRICS ===
    total_dispatches = len(supplier_dispatches)
    completed_dispatches = DispatchData.query.filter_by(from_user_id=user.id, status="Received").count()
    dispatch_efficiency = (completed_dispatches / total_dispatches * 100) if total_dispatches > 0 else 0
    return_rate = (total_returned / total_sent * 100) if total_sent > 0 else 0

    # Component usage for charts
    component_usage = []
    for comp_name, analytics in component_analytics.items():
        component_usage.append({
            'component': comp_name,
            'utilization': analytics['utilization_rate'],
            'flcs': analytics['total_sent']
        })

    # === FLC STATUS BREAKDOWN ===
    flc_status_breakdown = {
        'at_supplier': flc_at_supplier,
        'with_intermediates': flc_at_intermediate,
        'with_endusers': flc_at_enduser,
        'in_transit': 0,  # We can calculate pending dispatches if needed
        'pending_returns': total_sent - total_returned
    }

    # Calculate FLCs in transit (pending dispatches)
    in_transit_flcs = db.session.query(func.coalesce(func.sum(DispatchData.flc_qty), 0)).filter(
        DispatchData.from_user_id == user.id,
        DispatchData.status == "Pending"
    ).scalar() or 0
    flc_status_breakdown['in_transit'] = in_transit_flcs

    # === TIME-SERIES DATA FOR CHARTS ===
    today = datetime.utcnow().date()
    dates = []
    dispatch_counts = []
    return_counts = []

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

    # === PREPARE DATA FOR TEMPLATE ===
    flc_summary = {
        "at_supplier": flc_at_supplier,
        "at_intermediate": flc_at_intermediate,
        "at_enduser": flc_at_enduser,
        "total_sent": total_sent,
        "total_returned": total_returned,
        "baseline": total_baseline,
        "efficiency": round(dispatch_efficiency, 1),
        "return_rate": round(return_rate, 1),
        "utilization_rate": round(((total_sent - total_returned) / total_baseline * 100), 1) if total_baseline > 0 else 0,
        "total_components": len(components),
    }

    chart_data = {
        "dates": dates,
        "dispatch_trend": dispatch_counts,
        "return_trend": return_counts,
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

    # Template context
    template_context = {
        "stats": stats,
        "chart_data": json.dumps(chart_data),
        "flc_summary": flc_summary,
        "component_usage": component_usage,
        "component_analytics": component_analytics,
        "user_distribution": user_distribution,
        "flc_status_breakdown": flc_status_breakdown,
    }

    return render_template("supplier_analytics.html", **template_context)

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
