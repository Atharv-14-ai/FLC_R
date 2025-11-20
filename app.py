# app.py - ACID Compliant Version
from functools import wraps
import os
import re

from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy import cast, String, CheckConstraint, event, text
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import logging
import json

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError
# from werkzeug.security import safe_str_cmp

# Load .env if present
load_dotenv()

# --- App config ---
app = Flask(__name__, template_folder="templates", static_folder="static")

# ✅ FIXED: Database URL for Railway
database_url = os.environ.get("DATABASE_URL")
if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:1234@localhost:5432/flc"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "isolation_level": "READ COMMITTED"  # ✅ Set isolation level
}
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None

# --- Logging (debug friendly) ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
app.logger.setLevel(logging.DEBUG)

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)  # ✅ CSRF Protection


# ==================== TRANSACTION DECORATOR ====================
def transactional(f):
    """Decorator to ensure ACID atomicity with automatic rollback."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            if request.method == 'POST':
                db.session.commit()
                app.logger.info(f"Transaction committed in {f.__name__}")
            return result
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f"Integrity error in {f.__name__}: {str(e)}")
            flash("Data integrity error. Please check your input.", "danger")
            return redirect(request.referrer or url_for('dashboard'))
        except OperationalError as e:
            db.session.rollback()
            app.logger.error(f"Database error in {f.__name__}: {str(e)}")
            flash("Database operation failed. Please try again.", "danger")
            return redirect(request.referrer or url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception(f"Unexpected error in {f.__name__}: {str(e)}")
            flash(f"Operation failed: {str(e)}", "danger")
            return redirect(request.referrer or url_for('dashboard'))
    return decorated_function


# ==================== MODELS WITH CONSTRAINTS ====================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ✅ Add constraint
    __table_args__ = (
        CheckConstraint(
            "role IN ('Supplier', 'Intermediate', 'End User')",
            name='check_valid_role'
        ),
    )

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class DispatchData(db.Model):
    __tablename__ = "dispatch_data"
    id = db.Column(db.Integer, primary_key=True)

    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    to_end_user_id = db.Column(db.Integer, db.ForeignKey('end_users.id'), nullable=True, index=True)

    dispatch_type = db.Column(db.String(20), nullable=False, default="empty", index=True)
    parent_dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=True, index=True)

    from_role = db.Column(db.String(30), nullable=False)
    to_role = db.Column(db.String(30), nullable=False)
    component_id = db.Column(db.Integer, db.ForeignKey('components.id'), nullable=True, index=True)
    component = db.Column(db.String(100), nullable=False, index=True)  # Keep for compatibility

    # ✅ NEW: Add relationship
    component_rel = db.relationship("Component", foreign_keys=[component_id], backref="dispatches", lazy=True)
    

    flc_qty = db.Column(db.Integer, nullable=False)
    component_qty = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), default="Pending", index=True)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    sender = db.relationship("User", foreign_keys=[from_user_id], backref="dispatches_sent", lazy=True)
    receiver = db.relationship("User", foreign_keys=[to_user_id], backref="dispatches_received", lazy=True)
    parent = db.relationship("DispatchData", remote_side=[id], backref="children", lazy=True)

    # ✅ CONSISTENCY: Add constraints
    __table_args__ = (
        CheckConstraint('flc_qty > 0', name='check_flc_qty_positive'),
        CheckConstraint('component_qty >= 0', name='check_component_qty_non_negative'),
        CheckConstraint(
            "(to_user_id IS NOT NULL AND to_end_user_id IS NULL) OR "
            "(to_user_id IS NULL AND to_end_user_id IS NOT NULL)",
            name='check_recipient_exists'
        ),
        CheckConstraint(
            "dispatch_type IN ('empty', 'filled')",
            name='check_valid_dispatch_type'
        ),
        CheckConstraint(
            "status IN ('Pending', 'Received', 'Processed', 'Delivered', 'Returned', 'Partially Returned')",
            name='check_valid_status'
        ),
    )

    def __repr__(self):
        return f"<Dispatch {self.id} {self.from_role}->{self.to_role} ({self.dispatch_type}) x{self.flc_qty}>"


class Returned(db.Model):
    __tablename__ = "returned"
    id = db.Column(db.Integer, primary_key=True)
    dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=False, index=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    to_end_user_id = db.Column(db.Integer, db.ForeignKey('end_users.id'), nullable=True, index=True)
    flc_qty = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])
    end_user = db.relationship('EndUser', foreign_keys=[to_end_user_id])
    dispatch = db.relationship('DispatchData', foreign_keys=[dispatch_id])

    # ✅ Add constraint
    __table_args__ = (
        CheckConstraint('flc_qty > 0', name='check_returned_qty_positive'),
    )

    def __repr__(self):
        return f"<Return {self.id} dispatch:{self.dispatch_id} from_end_user:{self.to_end_user_id} x{self.flc_qty}>"


class Component(db.Model):
    __tablename__ = "components"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500), unique=True, nullable=False, index=True)
    description = db.Column(db.String(500), nullable=True)
    flc_stock = db.Column(db.Integer, nullable=False, default=100)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_fixed = db.Column(db.Boolean, default=False)
    fixed_date = db.Column(db.DateTime, nullable=True)

    # ✅ Add constraint
    __table_args__ = (
        CheckConstraint('flc_stock >= 0', name='check_stock_non_negative'),
    )

    def __repr__(self):
        return f"<Component {self.name} fixed={self.is_fixed}>"


class EndUser(db.Model):
    __tablename__ = 'end_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    location = db.Column(db.String(100))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<EndUser {self.name}>"


class InventoryConfig(db.Model):
    __tablename__ = "inventory_config"
    id = db.Column(db.Integer, primary_key=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    flc_stock = db.Column(db.Integer, nullable=False, default=100)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    supplier = db.relationship("User", backref="inventory_config")

    # ✅ Add constraint
    __table_args__ = (
        CheckConstraint('flc_stock >= 0', name='check_inventory_non_negative'),
    )


# ==================== AUTH / ROLE DECORATORS ====================
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


# ==================== AUTH ROUTES ====================
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            error = "Username and password are required"
            return render_template("index.html", error=error)
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["role"] = user.role
            session["username"] = user.username
            session.permanent = True
            app.logger.info(f"User {username} logged in successfully")
            flash("Logged in successfully", "success")
            return redirect(url_for("dashboard"))
        else:
            app.logger.warning(f"Failed login attempt for username: {username}")
            error = "Invalid username or password"
    
    # Generate CSRF token for the form
    return render_template("index.html", error=error)


@app.route("/add_user", methods=["GET", "POST"])
@login_required
@role_required("Supplier")
@transactional
def add_user():
    """Supplier (admin) can create users of any role, including Supplier."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()
        
        # ✅ Input validation
        if not username or not password or not role:
            error = "All fields required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif role not in ['Supplier', 'Intermediate', 'End User']:
            error = "Invalid role selected."
        elif User.query.filter_by(username=username).first():
            error = "Username already exists."
        else:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            u = User(username=username, password=hashed, role=role)
            db.session.add(u)
            # Commit handled by @transactional
            app.logger.info(f"User '{username}' created with role {role}")
            flash(f"User '{username}' created with role {role}.", "success")
            return redirect(url_for("add_user"))
    
    return render_template("add_user.html", error=error)


@app.route("/logout")
def logout():
    username = session.get("username", "Unknown")
    session.clear()
    app.logger.info(f"User {username} logged out")
    flash("Logged out", "info")
    return redirect(url_for("login"))


# ==================== DASHBOARD ====================
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

    try:
        if role == 'Supplier':
            sent_dispatches = DispatchData.query.filter_by(
                from_user_id=user_id
            ).order_by(DispatchData.date_time.desc()).limit(50).all()
            
            received_returns = Returned.query.filter_by(
                to_user_id=user_id
            ).order_by(Returned.date_time.desc()).limit(50).all()
            
            stats = build_stats(sent_dispatches)
            return render_template(
                "dashboard.html",
                role=role,
                sent_dispatches=sent_dispatches,
                received_returns=received_returns,
                stats=stats
            )

        elif role == 'Intermediate':
            received_dispatches = DispatchData.query.filter_by(
                to_user_id=user_id
            ).order_by(DispatchData.date_time.desc()).limit(50).all()
            
            sent_dispatches = DispatchData.query.filter_by(
                from_user_id=user_id
            ).order_by(DispatchData.date_time.desc()).limit(50).all()
            
            stats = build_stats(sent_dispatches)
            return render_template(
                "dashboard.html",
                role=role,
                received_dispatches=received_dispatches,
                sent_dispatches=sent_dispatches,
                stats=stats
            )
        else:
            flash("Invalid role session. Please log in again.", "danger")
            return redirect(url_for('logout'))
    
    except Exception as e:
        app.logger.exception(f"Dashboard error: {str(e)}")
        flash("Error loading dashboard", "danger")
        return redirect(url_for('logout'))


# ==================== DISPATCH CREATE ====================
@app.route('/dispatch_create', methods=['GET', 'POST'])
@login_required
@role_required('Supplier', 'Intermediate')
@transactional
def dispatch_create():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("User session invalid. Please log in again.", "danger")
        return redirect(url_for('login'))

    role = user.role
    components = Component.query.order_by(Component.name.asc()).all()

    if request.method == 'POST':
        # ✅ SUPPLIER → INTERMEDIATE (SYNCED VERSION)
        if role == 'Supplier':
            try:
                to_user_id = int(request.form['to_user'])
                component_ids = request.form.getlist('component_id[]')
                flc_qtys = request.form.getlist('flc_qty[]')
                comp_qtys = request.form.getlist('component_qty[]')
                remarks_list = request.form.getlist('remarks[]')
                
                # ✅ VALIDATION 1: Basic input integrity
                if not component_ids or not flc_qtys:
                    raise ValueError("At least one component must be selected")
                
                if len(component_ids) != len(flc_qtys) or len(component_ids) != len(comp_qtys):
                    raise ValueError("Mismatched input arrays")
                
                to_user = db.session.get(User, to_user_id)
                if not to_user or to_user.role != "Intermediate":
                    raise ValueError("Please select a valid Intermediate!")

                # ✅ ATOMIC PHASE 1: Lock ALL resources first
                supplier_inventory = db.session.query(InventoryConfig).with_for_update().filter_by(
                    supplier_id=user.id
                ).first()
                
                if not supplier_inventory:
                    raise ValueError("Supplier inventory not configured. Please contact administrator.")
                
                # ✅ Calculate requirements and lock all components
                total_flcs_dispatched = 0
                component_requirements = defaultdict(int)
                unique_component_ids = set()
                
                # Pre-validation without locks
                for i, (cid, fqty, cqty, rem) in enumerate(zip(component_ids, flc_qtys, comp_qtys, remarks_list)):
                    try:
                        comp_id = int(cid)
                        flc_qty_int = int(fqty)
                        comp_qty_int = int(cqty)
                    except (ValueError, TypeError):
                        raise ValueError(f"Invalid numeric input at position {i+1}")
                    
                    if flc_qty_int <= 0:
                        raise ValueError(f"FLC quantity must be positive for item {i+1}")
                    
                    if comp_qty_int < 0:
                        raise ValueError(f"Component quantity cannot be negative for item {i+1}")
                    
                    comp = Component.query.get(comp_id)
                    if not comp:
                        raise ValueError(f"Component ID {comp_id} not found")
                    
                    component_requirements[comp_id] += flc_qty_int
                    unique_component_ids.add(comp_id)
                    total_flcs_dispatched += flc_qty_int
                
                # ✅ LOCK all components involved
                locked_components = {}
                for comp_id in unique_component_ids:
                    comp = db.session.query(Component).with_for_update().get(comp_id)
                    if not comp:
                        raise ValueError(f"Component ID {comp_id} not found during locking")
                    locked_components[comp_id] = comp
                
                # ✅ VALIDATION 2: Check supplier inventory
                if supplier_inventory.flc_stock < total_flcs_dispatched:
                    raise ValueError(
                        f"Insufficient FLC inventory. Available: {supplier_inventory.flc_stock}, "
                        f"Requested: {total_flcs_dispatched}"
                    )
                
                # ✅ VALIDATION 3: Check individual component stocks
                for comp_id, required_flcs in component_requirements.items():
                    comp = locked_components[comp_id]
                    if comp.flc_stock < required_flcs:
                        raise ValueError(
                            f"Insufficient {comp.name} stock. Available: {comp.flc_stock}, "
                            f"Requested: {required_flcs}"
                        )
                
                # ✅ ATOMIC PHASE 2: Create dispatches and update BOTH inventory and component stocks
                dispatches_to_add = []
                for i, (cid, fqty, cqty, rem) in enumerate(zip(component_ids, flc_qtys, comp_qtys, remarks_list)):
                    comp_id = int(cid)
                    flc_qty_int = int(fqty)
                    comp_qty_int = int(cqty)
                    
                    comp = locked_components[comp_id]
                    
                    new_dispatch = DispatchData(
                        from_user_id=user.id,
                        to_user_id=to_user_id,
                        dispatch_type="empty",
                        parent_dispatch_id=None,
                        from_role="Supplier",
                        to_role="Intermediate",
                        component=comp.name,
                        component_id=comp.id,
                        flc_qty=flc_qty_int,
                        component_qty=comp_qty_int,
                        status="Pending",
                        remarks=rem,
                        date_time=datetime.utcnow()
                    )
                    dispatches_to_add.append(new_dispatch)
                    
                    # ✅ SYNCED: Reduce component stock
                    comp.flc_stock -= flc_qty_int
                    if comp.flc_stock < 0:
                        raise ValueError(f"Component {comp.name} stock would go negative!")
                
                # ✅ SYNCED: Update supplier inventory to match total component stocks
                total_component_stock = db.session.query(
                    func.coalesce(func.sum(Component.flc_stock), 0)
                ).scalar() or 0
                supplier_inventory.flc_stock = total_component_stock
                
                if supplier_inventory.flc_stock < 0:
                    raise ValueError("Supplier inventory would go negative. This should never happen!")
                
                # ✅ Add all dispatches
                db.session.add_all(dispatches_to_add)
                
                app.logger.info(
                    f"Supplier {user.username} dispatched {len(dispatches_to_add)} FLCs "
                    f"to Intermediate {to_user.username}. Inventory reduced to {supplier_inventory.flc_stock}"
                )
                flash(f"✅ {len(dispatches_to_add)} FLC dispatches created successfully!", "success")
                return redirect(url_for('dashboard'))

            except ValueError as e:
                db.session.rollback()
                flash(f"Error: {str(e)}", "danger")
                return redirect(url_for('dispatch_create'))
            except Exception as e:
                db.session.rollback()
                app.logger.exception("Error in supplier dispatch creation")
                flash("An unexpected error occurred. Please try again.", "danger")
                return redirect(url_for('dispatch_create'))

        # ✅ INTERMEDIATE → END USER (FIXED VERSION)
        elif role == 'Intermediate':  # CHANGED: This should be elif, not inside the Supplier block
            try:
                # Parse JSON data
                dispatch_data_json = request.form.get('dispatch_data')
                if not dispatch_data_json:
                    raise ValueError("No dispatch data provided")
                
                all_data = json.loads(dispatch_data_json)
                
                if not all_data:
                    raise ValueError("No dispatches to create")

                # ✅ ATOMIC PHASE 1: Pre-calculate and lock ALL parents first
                total_requirements = defaultdict(int)
                dispatch_groups = {}
                parent_ids = []
                
                for parent_id_str, dispatch_group in all_data.items():
                    parent_id = int(parent_id_str)
                    total_required = sum(int(entry['flc_qty']) for entry in dispatch_group)
                    
                    if total_required <= 0:
                        raise ValueError(f"Total requested FLCs must be positive for parent {parent_id}")
                    
                    total_requirements[parent_id] = total_required
                    dispatch_groups[parent_id] = dispatch_group
                    parent_ids.append(parent_id)
                
                # ✅ LOCK all parent dispatches in consistent order (prevent deadlocks)
                parent_ids.sort()
                locked_parents = {}
                
                for parent_id in parent_ids:
                    parent = db.session.query(DispatchData).with_for_update().get(parent_id)
                    
                    if not parent:
                        raise ValueError(f"Parent dispatch {parent_id} not found")
                    
                    if parent.to_user_id != user.id:
                        raise ValueError(f"You don't have access to dispatch {parent_id}")
                    
                    if parent.status not in ["Received", "Processed"]:
                        raise ValueError(f"Dispatch {parent_id} is not in receivable state: {parent.status}")
                    
                    # ✅ FIXED: Calculate used quantity WITHOUT FOR UPDATE (aggregate functions can't use FOR UPDATE)
                    used = db.session.query(
                        func.coalesce(func.sum(DispatchData.flc_qty), 0)
                    ).filter(
                        DispatchData.parent_dispatch_id == parent.id,
                        DispatchData.status.in_(["Delivered", "Pending", "Received"])
                    ).scalar() or 0  # REMOVED .with_for_update()
                    
                    available = parent.flc_qty - used
                    total_required = total_requirements[parent_id]
                    
                    if available <= 0:
                        raise ValueError(f"Dispatch #{parent.id} has no available FLCs")
                    
                    if total_required > available:
                        raise ValueError(
                            f"Only {available} FLCs available for Dispatch #{parent.id}, "
                            f"requested {total_required}"
                        )
                    
                    locked_parents[parent_id] = {
                        'object': parent,
                        'available': available,
                        'current_used': used,
                        'new_used': used
                    }
                
                # ✅ VALIDATION: Verify all end users exist
                end_user_ids = set()
                for dispatch_group in dispatch_groups.values():
                    for entry in dispatch_group:
                        end_user_id = int(entry['end_user_id'])
                        end_user_ids.add(end_user_id)
                
                end_users = {eu.id: eu for eu in EndUser.query.filter(EndUser.id.in_(end_user_ids)).all()}
                for end_user_id in end_user_ids:
                    if end_user_id not in end_users:
                        raise ValueError(f"End user {end_user_id} not found")
                
                # ✅ ATOMIC PHASE 2: Create all dispatches and update parents
                dispatches_to_add = []
                
                for parent_id in parent_ids:
                    dispatch_group = dispatch_groups[parent_id]
                    parent_data = locked_parents[parent_id]
                    parent = parent_data['object']
                    available = parent_data['available']
                    
                    current_consumed = 0
                    for entry in dispatch_group:
                        end_user_id = int(entry['end_user_id'])
                        flc_qty = int(entry['flc_qty'])
                        comp_qty = int(entry['component_qty'])
                        remarks = entry.get('remarks', '')

                        if flc_qty <= 0:
                            raise ValueError(f"FLC quantity must be positive for end user {end_user_id}")

                        # ✅ REAL-TIME AVAILABILITY CHECK
                        if current_consumed + flc_qty > available:
                            raise ValueError(
                                f"Dispatch would exceed available FLCs for parent #{parent_id}. "
                                f"Available: {available}, Already allocated: {current_consumed}, "
                                f"Requested: {flc_qty}"
                            )

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
                        dispatches_to_add.append(new_dispatch)
                        current_consumed += flc_qty
                    
                    # ✅ UPDATE parent consumption tracking
                    parent_data['new_used'] += current_consumed
                
                # ✅ ATOMIC PHASE 3: Update parent statuses based on final consumption
                for parent_id, parent_data in locked_parents.items():
                    parent = parent_data['object']
                    new_total_used = parent_data['new_used']
                    
                    # ✅ CONSISTENT STATUS LOGIC
                    if new_total_used >= parent.flc_qty:
                        parent.status = "Processed"
                    elif new_total_used > parent_data['current_used']:
                        parent.status = "Processed"
                
                # ✅ Add all dispatches at once
                db.session.add_all(dispatches_to_add)
                
                app.logger.info(
                    f"Intermediate {user.username} dispatched {len(dispatches_to_add)} FLCs "
                    f"to end users across {len(locked_parents)} parent dispatches"
                )
                flash(f"✅ {len(dispatches_to_add)} FLC dispatches to end users created successfully!", "success")
                return redirect(url_for('dashboard'))

            except json.JSONDecodeError:
                db.session.rollback()
                flash("Error: Invalid dispatch data format", "danger")
                return redirect(url_for('dispatch_create'))
            except (ValueError, KeyError) as e:
                db.session.rollback()
                flash(f"Error: {str(e)}", "danger")
                return redirect(url_for('dispatch_create'))
            except Exception as e:
                db.session.rollback()
                app.logger.exception("Error in intermediate dispatch creation")
                flash("An unexpected error occurred. Please try again.", "danger")
                return redirect(url_for('dispatch_create'))

    # ========== GET REQUEST ==========
    if role == 'Supplier':
        intermediates = User.query.filter_by(role="Intermediate").order_by(User.username).all()
        
        # Get current inventory for display
        supplier_inventory = InventoryConfig.query.filter_by(supplier_id=user.id).first()
        available_flcs = supplier_inventory.flc_stock if supplier_inventory else 0
        
        component_stocks = []
        for comp in components:
            component_stocks.append({
                'id': comp.id,
                'name': comp.name,
                'available_stock': comp.flc_stock
            })
        
        return render_template(
            'dispatch_create.html', 
            role=role, 
            users=intermediates, 
            components=components,
            available_flcs=available_flcs,
            component_stocks=component_stocks
        )

    elif role == 'Intermediate':
        end_users = EndUser.query.order_by(EndUser.name.asc()).all()
        received_dispatches = DispatchData.query.filter(
            DispatchData.to_user_id == user.id,
            DispatchData.status.in_(["Received", "Processed"])
        ).all()

        parent_list = []
        for d in received_dispatches:
            consumed = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.parent_dispatch_id == d.id,
                DispatchData.status.in_(["Delivered", "Pending", "Received"])
            ).scalar() or 0
            
            available = d.flc_qty - consumed
            if available > 0:
                parent_list.append({
                    'dispatch': d,
                    'available': available,
                    'consumed': consumed,
                    'component': d.component
                })

        return render_template(
            'dispatch_create.html',
            role=role,
            users=end_users,
            parent_dispatches=parent_list
        )

    flash("Unauthorized role!", "danger")
    return redirect(url_for('dashboard'))
    

# ==================== RECEIVE ====================
@app.route("/dispatch_receive", methods=["GET", "POST"])
@login_required
@role_required('Supplier', 'Intermediate')
@transactional
def dispatch_receive():
    user_id = session.get("user_id")
    role = session.get("role")

    if request.method == "POST":
        try:
            dispatch_id = int(request.form.get("dispatch_id"))
            
            # ✅ ISOLATION: Lock the dispatch row
            dispatch = db.session.query(DispatchData).with_for_update().get(dispatch_id)

            if not dispatch:
                raise ValueError("Dispatch not found")
            
            if dispatch.to_user_id != user_id:
                raise ValueError("You are not authorized to receive this dispatch")
            
            if dispatch.status in ["Received", "Returned"]:
                flash(f"Dispatch {dispatch_id} already marked as {dispatch.status}", "info")
                return redirect(url_for("dispatch_receive"))

            dispatch.status = "Received"
            # Commit handled by @transactional
            
            app.logger.info(f"User {user_id} received dispatch {dispatch_id}")
            flash(f"Dispatch {dispatch_id} marked Received ✅", "success")
            return redirect(url_for("dispatch_receive"))

        except ValueError as e:
            raise
        except Exception as e:
            app.logger.exception("Error receiving dispatch")
            raise

    # GET Request
    if role == "Supplier":
        dispatches = DispatchData.query.filter(
            DispatchData.to_user_id == user_id,
            DispatchData.status == "Pending"
        ).order_by(DispatchData.date_time.desc()).all()

    elif role == "Intermediate":
        dispatches = DispatchData.query.filter(
            DispatchData.to_user_id == user_id,
            DispatchData.status == "Pending"
        ).order_by(DispatchData.date_time.desc()).all()
    else:
        dispatches = []

    return render_template("dispatch_receive.html", dispatches=dispatches, error=None)


# ==================== RETURNS ====================
@app.route('/returns', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
@transactional
def returns():
    current_user_id = session.get("user_id")
    current_user = User.query.get(current_user_id)

    if not current_user or current_user.role != 'Supplier':
        flash("Only suppliers can record returns.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            dispatch_id = int(request.form.get('dispatch_id', 0))
            end_user_id = int(request.form.get('end_user_id', 0))
            flc_qty = int(request.form.get('flc_qty', 0))
            remarks = request.form.get('remarks', '').strip()

            # ✅ VALIDATION 1: Basic input validation
            if dispatch_id <= 0:
                raise ValueError("Invalid dispatch selected")
            
            if end_user_id <= 0:
                raise ValueError("Please select a valid end user")
            
            if flc_qty <= 0:
                raise ValueError("Returned quantity must be positive")

            # ✅ ATOMIC PHASE 1: Lock ALL resources first
            dispatch = db.session.query(DispatchData).with_for_update().get(dispatch_id)
            end_user = db.session.get(EndUser, end_user_id)
            
            if not dispatch:
                raise ValueError("Invalid dispatch selected")
            
            if not end_user:
                raise ValueError("Please select a valid end user")

            # ✅ Validate dispatch belongs to current user
            if dispatch.from_user_id != current_user.id:
                raise ValueError("You can only record returns for your own dispatches")

            # ✅ LOCK: Supplier inventory
            supplier_inventory = db.session.query(InventoryConfig).with_for_update().filter_by(
                supplier_id=current_user.id
            ).first()
            
            if not supplier_inventory:
                raise ValueError("Supplier inventory not configured")

            # ✅ FIXED: Find component by name (more reliable than direct query)
            component = Component.query.filter_by(name=dispatch.component).first()
            if not component:
                # Try to find any component that matches (case-insensitive)
                component = Component.query.filter(
                    func.lower(Component.name) == func.lower(dispatch.component)
                ).first()
                if not component:
                    raise ValueError(f"Component '{dispatch.component}' not found in database")

            # ✅ FIXED: Calculate totals WITHOUT FOR UPDATE (aggregate functions)
            total_returned_all = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).filter_by(dispatch_id=dispatch_id).scalar() or 0

            # ✅ FIXED: Get end user dispatches
            end_user_dispatches = DispatchData.query.filter(
                DispatchData.parent_dispatch_id == dispatch_id,
                DispatchData.to_end_user_id == end_user_id
            ).all()
            
            if not end_user_dispatches:
                raise ValueError("Selected end user did not receive FLCs from this dispatch")

            # ✅ Calculate totals with data
            total_sent_to_end_user = sum(d.flc_qty for d in end_user_dispatches)
            
            total_returned_from_end_user = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).filter(
                Returned.dispatch_id == dispatch_id,
                Returned.to_end_user_id == end_user_id
            ).scalar() or 0
            
            remaining_from_end_user = total_sent_to_end_user - total_returned_from_end_user

            # ✅ VALIDATION 2: Business logic validation
            if remaining_from_end_user <= 0:
                raise ValueError(f"All FLCs from {end_user.name} for this dispatch have already been returned")

            if flc_qty > remaining_from_end_user:
                raise ValueError(
                    f"Cannot return {flc_qty} FLCs — {end_user.name} only has "
                    f"{remaining_from_end_user} remaining from this dispatch"
                )

            # ✅ ATOMIC PHASE 2: Record return AND update inventory
            new_return = Returned(
                dispatch_id=dispatch.id,
                from_user_id=current_user.id,
                to_user_id=dispatch.from_user_id,
                to_end_user_id=end_user_id,
                flc_qty=flc_qty,
                remarks=remarks,
                date_time=datetime.utcnow()
            )
            db.session.add(new_return)

            # ✅ UPDATE: Increase component stock
            component.flc_stock += flc_qty

            # ✅ SYNCED: Update supplier inventory to match total component stocks
            total_component_stock = db.session.query(
                func.coalesce(func.sum(Component.flc_stock), 0)
            ).scalar() or 0
            supplier_inventory.flc_stock = total_component_stock

            # ✅ UPDATE: Dispatch status based on new total returns
            new_total_returned_all = total_returned_all + flc_qty
            
            if new_total_returned_all >= dispatch.flc_qty:
                dispatch.status = "Returned"
            elif new_total_returned_all > 0:
                dispatch.status = "Partially Returned"

            # ✅ FINAL VALIDATION: Ensure no negative stocks
            if supplier_inventory.flc_stock < 0:
                raise ValueError("Supplier inventory would be negative. This should never happen!")
            
            if component.flc_stock < 0:
                raise ValueError(f"Component {component.name} stock would be negative. This should never happen!")

            app.logger.info(
                f"Return of {flc_qty} FLCs from end user {end_user_id} recorded for dispatch {dispatch_id}. "
                f"Inventory synced to {supplier_inventory.flc_stock}"
            )
            flash(f"Return of {flc_qty} FLCs from {end_user.name} recorded successfully. Inventory updated.", "success")
            return redirect(url_for('returns'))

        except ValueError as e:
            raise
        except Exception as e:
            app.logger.exception("Error recording return")
            raise

    # GET REQUEST (No locking needed for read-only operations)
    try:
        active_dispatches = DispatchData.query.filter_by(
            from_user_id=current_user.id
        ).filter(
            DispatchData.status.in_(["Pending", "Partially Returned", "Received", "Processed"])
        ).order_by(DispatchData.date_time.desc()).all()

        dispatches = []
        for d in active_dispatches:
            # Calculate total returned for this dispatch
            total_returned = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).filter_by(dispatch_id=d.id).scalar() or 0
            
            remaining = d.flc_qty - total_returned

            # Only include dispatches that have remaining FLCs to return
            if remaining > 0:
                # Get all end users who received FLCs from this dispatch
                end_users = db.session.query(EndUser).join(
                    DispatchData, DispatchData.to_end_user_id == EndUser.id
                ).filter(
                    DispatchData.parent_dispatch_id == d.id
                ).distinct().all()
                
                end_user_data = []
                for eu in end_users:
                    # Calculate total sent to this end user
                    sent_to_end_user = db.session.query(
                        func.coalesce(func.sum(DispatchData.flc_qty), 0)
                    ).filter(
                        DispatchData.parent_dispatch_id == d.id,
                        DispatchData.to_end_user_id == eu.id
                    ).scalar() or 0
                    
                    # Calculate total returned from this end user
                    returned_from_end_user = db.session.query(
                        func.coalesce(func.sum(Returned.flc_qty), 0)
                    ).filter(
                        Returned.dispatch_id == d.id,
                        Returned.to_end_user_id == eu.id
                    ).scalar() or 0
                    
                    remaining_end_user = sent_to_end_user - returned_from_end_user
                    
                    # Only include end users who have remaining FLCs to return
                    if remaining_end_user > 0:
                        end_user_data.append({
                            'id': eu.id,
                            'name': eu.name,
                            'location': eu.location,
                            'sent': sent_to_end_user,
                            'returned': returned_from_end_user,
                            'remaining': remaining_end_user
                        })
                
                # Only add dispatch if it has end users with remaining FLCs
                if end_user_data:
                    dispatches.append({
                        'dispatch': d,
                        'total_returned': total_returned,
                        'remaining': remaining,
                        'end_users': end_user_data
                    })

        # Show all returns with end user information
        all_returns = Returned.query.options(
            db.joinedload(Returned.end_user),
            db.joinedload(Returned.from_user),
            db.joinedload(Returned.dispatch)
        ).order_by(Returned.date_time.desc()).limit(50).all()

        return render_template('returns.html', dispatches=dispatches, returns=all_returns)

    except Exception as e:
        app.logger.exception("Error loading returns page")
        flash("Error loading returns data", "danger")
        return redirect(url_for('dashboard'))


# ==================== API ENDPOINT ====================
@app.route('/api/dispatch/<int:dispatch_id>/endusers')
@login_required
def get_endusers_for_dispatch(dispatch_id):
    """Get end users who received FLCs from this dispatch and their remaining quantities"""
    current_user_id = session.get("user_id")
    
    dispatch = DispatchData.query.filter_by(
        id=dispatch_id,
        from_user_id=current_user_id
    ).first()
    
    if not dispatch:
        return jsonify([])
    
    end_users = db.session.query(EndUser).join(
        DispatchData, DispatchData.to_end_user_id == EndUser.id
    ).filter(
        DispatchData.parent_dispatch_id == dispatch_id
    ).distinct().all()
    
    result = []
    for eu in end_users:
        sent_to_end_user = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.parent_dispatch_id == dispatch_id,
            DispatchData.to_end_user_id == eu.id
        ).scalar() or 0
        
        returned_from_end_user = db.session.query(
            func.coalesce(func.sum(Returned.flc_qty), 0)
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


# ==================== USER MANAGEMENT ====================
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
@transactional
def manage_users():
    """Supplier manages only Intermediate users."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            raise ValueError('Username and Password required!')

        if len(password) < 6:
            raise ValueError('Password must be at least 6 characters')

        if User.query.filter_by(username=username).first():
            raise ValueError('Username already exists!')

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed, role='Intermediate')
        db.session.add(new_user)
        # Commit handled by @transactional
        
        app.logger.info(f"Intermediate user '{username}' created")
        flash(f"✅ Intermediate '{username}' added successfully.", 'success')
        return redirect(url_for('manage_users'))

    intermediates = User.query.filter_by(role='Intermediate').order_by(User.username).all()
    return render_template('manage_users.html', intermediates=intermediates)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
@transactional
def edit_user(user_id):
    """Edit a non-Supplier user."""
    user = User.query.get_or_404(user_id)

    if user.role == 'Supplier':
        flash('Cannot edit Supplier account here.', 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        if not username or role not in ('Intermediate', 'End User'):
            raise ValueError('Invalid input. Username required and role must be Intermediate or End User.')

        existing = User.query.filter(
            User.username == username,
            User.id != user.id
        ).first()
        
        if existing:
            raise ValueError('Username already taken by another account.')

        user.username = username
        user.role = role

        if password:
            if len(password) < 6:
                raise ValueError('Password must be at least 6 characters')
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Commit handled by @transactional
        app.logger.info(f"User {user_id} updated")
        flash('✅ User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('Supplier')
@transactional
def delete_user(user_id):
    """Safely delete a non-Supplier user and handle related dependencies."""
    user = User.query.get(user_id)
    
    if not user:
        raise ValueError('User not found.')

    if user.role == 'Supplier':
        raise ValueError('Cannot delete Supplier account.')

    # ✅ Use cascade deletes in atomic transaction
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

    db.session.delete(user)
    # Commit handled by @transactional
    
    app.logger.info(f"User {user_id} ({user.username}) deleted")
    flash('✅ User deleted successfully.', 'success')
    return redirect(url_for('manage_users'))


# ==================== COMPONENT MANAGEMENT ====================
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
@transactional
def add_component():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        stock_qty = request.form.get('stock_qty', 0, type=int)

        if not name:
            raise ValueError("Component name required!")

        if Component.query.filter_by(name=name).first():
            raise ValueError("Component already exists!")

        # ✅ SYNCED: Create component AND update inventory together
        comp = Component(
            name=name,
            description=description,
            flc_stock=stock_qty,  # Component's own stock
            created_by=session.get("user_id")
        )
        db.session.add(comp)

        # ✅ SYNCED: Update supplier inventory to match total components
        supplier_inventory = db.session.query(InventoryConfig).with_for_update().filter_by(
            supplier_id=session.get("user_id")
        ).first()
        
        if supplier_inventory:
            # Calculate new total inventory (sum of all component stocks)
            total_component_stock = db.session.query(
                func.coalesce(func.sum(Component.flc_stock), 0)
            ).scalar() or 0
            supplier_inventory.flc_stock = total_component_stock
        else:
            supplier_inventory = InventoryConfig(
                supplier_id=session.get("user_id"), 
                flc_stock=stock_qty
            )
            db.session.add(supplier_inventory)

        flash(f"✅ Component '{name}' added successfully! Total inventory updated to {supplier_inventory.flc_stock} FLCs.", "success")
        return redirect(url_for('components'))

    return render_template("add_component.html")



@app.route('/edit_component/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
@transactional
def edit_component(id):
    component = Component.query.get_or_404(id)

    if request.method == 'POST':
        old_stock = component.flc_stock
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        new_stock = request.form.get('flc_stock', component.flc_stock, type=int)

        if not name:
            raise ValueError("Component name required!")

        if new_stock < 0:
            raise ValueError("Stock quantity cannot be negative!")

        component.name = name
        component.description = description
        component.flc_stock = new_stock

        # ✅ SYNCED: Update supplier inventory to reflect component stock change
        supplier_inventory = db.session.query(InventoryConfig).with_for_update().filter_by(
            supplier_id=session.get("user_id")
        ).first()
        
        if supplier_inventory:
            # Recalculate total inventory based on all components
            total_component_stock = db.session.query(
                func.coalesce(func.sum(Component.flc_stock), 0)
            ).scalar() or 0
            supplier_inventory.flc_stock = total_component_stock

        app.logger.info(f"Component {id} updated. Inventory synced to {supplier_inventory.flc_stock}")
        flash(f"✅ Component '{component.name}' updated successfully! Inventory synced.", "success")
        return redirect(url_for('components'))

    return render_template("edit_component.html", component=component)


@app.route('/delete_component/<int:component_id>', methods=['POST'])
@login_required
@role_required('Supplier')
@transactional
def delete_component(component_id):
    component = Component.query.get_or_404(component_id)
    
    # ✅ SYNCED: Get stock before deletion for inventory update
    component_stock = component.flc_stock
    
    db.session.delete(component)

    # ✅ SYNCED: Update supplier inventory after deletion
    supplier_inventory = db.session.query(InventoryConfig).with_for_update().filter_by(
        supplier_id=session.get("user_id")
    ).first()
    
    if supplier_inventory:
        total_component_stock = db.session.query(
            func.coalesce(func.sum(Component.flc_stock), 0)
        ).scalar() or 0
        supplier_inventory.flc_stock = total_component_stock

    app.logger.info(f"Component {component_id} deleted. Inventory synced to {supplier_inventory.flc_stock}")
    flash('✅ Component deleted successfully. Inventory synced.', 'success')
    return redirect(url_for('components'))


# ==================== END USER MANAGEMENT ====================
@app.route('/manage_end_users', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
@transactional
def manage_end_users():
    """Supplier can add and view End Users."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location = request.form.get('location', '').strip()
        remarks = request.form.get('remarks', '').strip()

        if not name:
            raise ValueError("End User name is required.")

        new_user = EndUser(name=name, location=location, remarks=remarks)
        db.session.add(new_user)
        # Commit handled by @transactional
        
        app.logger.info(f"End user '{name}' added")
        flash(f"✅ End User '{name}' added successfully.", "success")
        return redirect(url_for('manage_end_users'))

    end_users = EndUser.query.order_by(EndUser.created_at.desc()).all()
    return render_template('manage_end_users.html', end_users=end_users)


@app.route('/edit_end_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
@transactional
def edit_end_user(user_id):
    user = EndUser.query.get_or_404(user_id)
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location = request.form.get('location', '').strip()
        remarks = request.form.get('remarks', '').strip()

        if not name:
            raise ValueError("End User name is required.")

        user.name = name
        user.location = location
        user.remarks = remarks
        # Commit handled by @transactional
        
        app.logger.info(f"End user {user_id} updated")
        flash(f"✏️ End User '{user.name}' updated successfully.", "success")
        return redirect(url_for('manage_end_users'))
    
    return render_template('edit_end_user.html', user=user)


@app.route('/delete_end_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('Supplier')
@transactional
def delete_end_user(user_id):
    user = EndUser.query.get_or_404(user_id)
    db.session.delete(user)
    # Commit handled by @transactional
    
    app.logger.info(f"End user {user_id} deleted")
    flash(f"🗑️ End User '{user.name}' deleted successfully.", "success")
    return redirect(url_for('manage_end_users'))


# ==================== REPORTS ====================
@app.route("/reports")
@login_required
def reports():
    user_id = session.get("user_id")
    role = session.get("role")

    cycle_report = []
    pending_returns = []
    remarks_list = []

    try:
        if role == "Supplier":
            supplier_dispatches = DispatchData.query.filter_by(
                from_user_id=user_id,
                dispatch_type="empty"
            ).order_by(DispatchData.date_time.desc()).all()

            for d in supplier_dispatches:
                returned_qty = db.session.query(
                    func.coalesce(func.sum(Returned.flc_qty), 0)
                ).filter(
                    Returned.dispatch_id == d.id,
                    Returned.to_user_id == user_id
                ).scalar() or 0
                
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
            received_from_supplier = DispatchData.query.filter_by(
                to_user_id=user_id,
                dispatch_type="empty"
            ).order_by(DispatchData.date_time.desc()).all()

            sent_to_enduser = DispatchData.query.filter_by(
                from_user_id=user_id,
                dispatch_type="filled"
            ).order_by(DispatchData.date_time.desc()).all()

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

        return render_template(
            "reports.html",
            cycle_report=cycle_report,
            pending_returns=pending_returns,
            remarks=remarks_list,
            role=role
        )
    
    except Exception as e:
        app.logger.exception("Error generating reports")
        flash("Error generating reports", "danger")
        return redirect(url_for('dashboard'))


# ==================== ANALYTICS ====================
@app.route("/reports/analytics")
@login_required
@role_required("Supplier")
def supplier_analytics():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash("Session expired or user not found. Please log in again.", "danger")
        return redirect(url_for("logout"))

    try:
        # ✅ CORRECTED: Get total baseline from components
        total_baseline = db.session.query(
            func.coalesce(func.sum(Component.flc_stock), 0)
        ).scalar() or 0
        
        # ✅ CORRECTED: Calculate total sent FLCs
        total_sent = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.from_user_id == user.id,
            DispatchData.dispatch_type == "empty"
        ).scalar() or 0

        # ✅ CORRECTED: Calculate total returned FLCs
        total_returned = db.session.query(
            func.coalesce(func.sum(Returned.flc_qty), 0)
        ).filter(
            Returned.to_user_id == user.id
        ).scalar() or 0

        # ✅ CORRECTED: Calculate FLCs at supplier (current inventory)
        flc_at_supplier = total_baseline  # This should be current component stock total
        
        # Get supplier inventory for accurate current stock
        supplier_inventory = InventoryConfig.query.filter_by(supplier_id=user.id).first()
        if supplier_inventory:
            flc_at_supplier = supplier_inventory.flc_stock

        # Use a consistent snapshot for all queries
        supplier_dispatches = DispatchData.query.filter_by(
            from_user_id=user.id,
            dispatch_type="empty"
        ).all()

        # Intermediate FLC calculation
        intermediate_flc_data = {}
        
        for dispatch in supplier_dispatches:
            if dispatch.to_user_id not in intermediate_flc_data:
                intermediate_flc_data[dispatch.to_user_id] = {
                    'username': dispatch.receiver.username if dispatch.receiver else 'Unknown',
                    'components': {},
                    'total_flcs': 0
                }
            
            consumed = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(DispatchData.parent_dispatch_id == dispatch.id).scalar() or 0
            
            available = dispatch.flc_qty - consumed
            
            if dispatch.component not in intermediate_flc_data[dispatch.to_user_id]['components']:
                intermediate_flc_data[dispatch.to_user_id]['components'][dispatch.component] = 0
            
            intermediate_flc_data[dispatch.to_user_id]['components'][dispatch.component] += available
            intermediate_flc_data[dispatch.to_user_id]['total_flcs'] += available

        user_distribution = {'intermediates': [], 'end_users': []}
        
        for intermediate_id, data in intermediate_flc_data.items():
            if data['total_flcs'] > 0:
                components_list = [
                    {'name': comp, 'flcs': qty}
                    for comp, qty in data['components'].items()
                    if qty > 0
                ]
                
                user_distribution['intermediates'].append({
                    'username': data['username'],
                    'role': 'Intermediate',
                    'total_flcs': data['total_flcs'],
                    'components': components_list
                })

        # End user FLC calculation
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
            
            returned_qty = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).filter(
                Returned.dispatch_id == dispatch.parent_dispatch_id,
                Returned.to_end_user_id == dispatch.to_end_user_id
            ).scalar() or 0
            
            net_flcs = dispatch.flc_qty - returned_qty
            
            if net_flcs > 0:
                end_user_flc_data[dispatch.to_end_user_id]['components'][dispatch.component] += net_flcs
                end_user_flc_data[dispatch.to_end_user_id]['total_flcs'] += net_flcs

        for end_user_id, data in end_user_flc_data.items():
            if data['total_flcs'] > 0:
                components_list = [
                    {'name': comp, 'flcs': qty}
                    for comp, qty in data['components'].items()
                    if qty > 0
                ]
                
                user_distribution['end_users'].append({
                    'name': data['name'],
                    'location': data['location'],
                    'role': 'End User',
                    'total_flcs': data['total_flcs'],
                    'components': components_list,
                    'intermediate': data['intermediate']
                })

        flc_at_intermediate = sum(user['total_flcs'] for user in user_distribution['intermediates'])
        flc_at_enduser = sum(user['total_flcs'] for user in user_distribution['end_users'])

        # Component analytics
        components = Component.query.all()
        component_analytics = {}
        
        for component in components:
            component_sent = db.session.query(
                func.coalesce(func.sum(DispatchData.flc_qty), 0)
            ).filter(
                DispatchData.from_user_id == user.id,
                DispatchData.dispatch_type == "empty",
                DispatchData.component == component.name
            ).scalar() or 0

            component_returned = db.session.query(
                func.coalesce(func.sum(Returned.flc_qty), 0)
            ).join(DispatchData, Returned.dispatch_id == DispatchData.id).filter(
                Returned.to_user_id == user.id,
                DispatchData.component == component.name
            ).scalar() or 0

            component_at_supplier = component.flc_stock - component_sent + component_returned
            
            component_at_intermediate = 0
            for intermediate in user_distribution['intermediates']:
                for comp in intermediate['components']:
                    if comp['name'] == component.name:
                        component_at_intermediate += comp['flcs']
            
            component_at_enduser = 0
            for end_user in user_distribution['end_users']:
                for comp in end_user['components']:
                    if comp['name'] == component.name:
                        component_at_enduser += comp['flcs']

            utilization_rate = 0
            if component.flc_stock > 0:
                utilization_rate = round(
                    ((component_sent - component_returned) / component.flc_stock * 100),
                    1
                )

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

        # Business metrics
        total_dispatches = len(supplier_dispatches)
        completed_dispatches = DispatchData.query.filter_by(
            from_user_id= user.id,
            status="Received"
        ).count()
        
        dispatch_efficiency = (completed_dispatches / total_dispatches * 100) if total_dispatches > 0 else 0
        return_rate = (total_returned / total_sent * 100) if total_sent > 0 else 0

        component_usage = []
        for comp_name, analytics in component_analytics.items():
            component_usage.append({
                'component': comp_name,
                'utilization': analytics['utilization_rate'],
                'flcs': analytics['total_sent']
            })

        # ✅ CORRECTED: FLC Status Breakdown
        flc_status_breakdown = {
            'at_supplier': flc_at_supplier,  # Current inventory
            'with_intermediates': flc_at_intermediate,  # With intermediates
            'with_endusers': flc_at_enduser,  # With end users
            'pending_returns': total_sent - total_returned  # Still in circulation
        }

        in_transit_flcs = db.session.query(
            func.coalesce(func.sum(DispatchData.flc_qty), 0)
        ).filter(
            DispatchData.from_user_id==user.id,
            DispatchData.status == "Pending"
        ).scalar() or 0
        
        flc_status_breakdown['in_transit'] = in_transit_flcs

        # Time-series data
        today = datetime.utcnow().date()
        dates = []
        dispatch_counts = []
        return_counts = []

        for i in range(29, -1, -1):
            day = today - timedelta(days=i)
            dates.append(day.strftime("%m/%d"))
            
            day_dispatch = DispatchData.query.filter(
                DispatchData.from_user_id==user.id,
                func.date(DispatchData.date_time) == day
            ).count()
            dispatch_counts.append(day_dispatch)
            
            day_returns = Returned.query.filter(
                Returned.to_user_id==user.id,
                func.date(Returned.date_time) == day
            ).count()
            return_counts.append(day_returns)

        # ✅ CORRECTED: FLC Summary
        flc_summary = {
            "at_supplier": flc_at_supplier,
            "at_intermediate": flc_at_intermediate,
            "at_enduser": flc_at_enduser,
            "total_sent": total_sent,
            "total_returned": total_returned,
            "baseline": total_baseline,  # Original total capacity
            "efficiency": round(dispatch_efficiency, 1),
            "return_rate": round(return_rate, 1),
            "utilization_rate": round(((total_sent - total_returned) / total_baseline * 100), 1) if total_baseline > 0 else 0,
        }

        stats = {
            "total_dispatches": total_dispatches,
            "pending": DispatchData.query.filter_by(from_user_id=user.id, status="Pending").count(),
            "received": completed_dispatches,
            "returned": Returned.query.filter_by(to_user_id=user.id).count(),
            "efficiency": round(dispatch_efficiency, 1),
            "return_rate": round(return_rate, 1),
            "utilization_rate": flc_summary["utilization_rate"],
            "total_components": len(components),
            "active_components": len([c for c in component_analytics.values() if c['total_sent'] > 0]),
            "active_intermediates": len(user_distribution['intermediates']),
            "active_end_users": len(user_distribution['end_users'])
        }

        # Prepare chart data
        chart_data = {
            'dates': dates,
            'dispatch_counts': dispatch_counts,
            'return_counts': return_counts,
            'component_usage': component_usage,
            'flc_status_breakdown': flc_status_breakdown
        }

        return render_template(
            "supplier_analytics.html",
            stats=stats,
            flc_summary=flc_summary,
            component_analytics=component_analytics,
            user_distribution=user_distribution,
            flc_status_breakdown=flc_status_breakdown,
            chart_data=chart_data
        )

    except Exception as e:
        app.logger.exception(f"Error in supplier analytics: {str(e)}")
        flash("Error generating analytics report. Please try again.", "danger")
        return render_template(
            "supplier_analytics.html",
            stats={},
            flc_summary={},
            component_analytics={},
            user_distribution={'intermediates': [], 'end_users': []},
            flc_status_breakdown={},
            chart_data={}
        )


# ==================== INVENTORY MANAGEMENT ====================
@app.route("/update_inventory", methods=["POST"])
@login_required
@role_required("Supplier")
@transactional
def update_inventory():
    """Allow supplier to add new FLCs to their inventory AND sync with components."""
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash("Session expired or user not found. Please log in again.", "danger")
        return redirect(url_for("logout"))

    try:
        add_qty = int(request.form.get("add_qty", 0))
    except ValueError:
        raise ValueError("Invalid input! Please enter a valid number.")

    if add_qty <= 0:
        raise ValueError("Quantity must be greater than zero.")

    # ✅ LOCK: Inventory and ALL components
    inventory = db.session.query(InventoryConfig).with_for_update().filter_by(supplier_id=user.id).first()
    components = db.session.query(Component).with_for_update().all()
    
    if not inventory:
        inventory = InventoryConfig(supplier_id=user.id, flc_stock=add_qty)
        db.session.add(inventory)
        msg = f"Inventory initialized with {add_qty} FLCs ✅"
    else:
        inventory.flc_stock += add_qty
        msg = f"Added {add_qty} new FLCs to your inventory ✅"
    
    # ✅ SYNCED: Also update ALL component stocks proportionally
    components_updated = 0
    if components:
        # Distribute the new FLCs equally among all components
        base_increase = add_qty // len(components)
        remainder = add_qty % len(components)
        
        for i, component in enumerate(components):
            increase = base_increase + (1 if i < remainder else 0)
            component.flc_stock += increase
            components_updated += 1

    app.logger.info(
        f"Inventory updated for supplier {user.username}: +{add_qty} FLCs. "
        f"Updated {components_updated} components."
    )
    flash(f"{msg} and {components_updated} component stocks updated!", "success")
    return redirect(url_for("supplier_analytics"))


# ==================== HEALTH CHECK & ERROR HANDLERS ====================
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    app.logger.warning(f"404 error: {request.url}")
    
    # For API requests, return JSON
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Page not found'}), 404
    
    # For browser requests, redirect with flash message
    if session.get('user_id'):
        flash("The requested page was not found.", "warning")
        return redirect(url_for('dashboard'))
    else:
        flash("Page not found. Please log in.", "warning")
        return redirect(url_for('login'))


@app.errorhandler(500)
def internal_server_error(error):
    """Handle 500 errors gracefully"""
    app.logger.error(f"500 error: {str(error)}")
    
    # For API requests, return JSON
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Internal server error'}), 500
    
    # For browser requests, redirect with flash message
    if session.get('user_id'):
        flash("An unexpected error occurred. Please try again.", "danger")
        return redirect(url_for('dashboard'))
    else:
        flash("An error occurred. Please log in again.", "danger")
        return redirect(url_for('login'))


@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    app.logger.warning(f"403 error: {request.url} - User: {session.get('user_id')}")
    
    # For API requests, return JSON
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Access forbidden'}), 403
    
    flash("You don't have permission to access this page.", "danger")
    return redirect(url_for('dashboard'))


@app.errorhandler(413)
def too_large_error(error):
    """Handle 413 errors (file too large)"""
    app.logger.warning(f"413 error: {request.url} - File too large")
    flash("The file you uploaded is too large.", "warning")
    return redirect(request.referrer or url_for('dashboard'))


@app.errorhandler(400)
def bad_request_error(error):
    """Handle 400 errors"""
    app.logger.warning(f"400 error: {request.url}")
    
    # For API requests, return JSON
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Bad request'}), 400
    
    flash("Bad request. Please check your input.", "warning")
    return redirect(request.referrer or url_for('dashboard'))


@app.errorhandler(401)
def unauthorized_error(error):
    """Handle 401 errors"""
    app.logger.warning(f"401 error: {request.url}")
    
    # For API requests, return JSON
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Unauthorized'}), 401
    
    flash("Please log in to access this page.", "warning")
    return redirect(url_for('login'))


# ==================== DATABASE INITIALIZATION ====================
def init_db():
    """Initialize database tables and create default admin user if needed"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            app.logger.info("Database tables created/verified")
            
            # Create default admin user if no users exist
            if not User.query.first():
                hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
                admin_user = User(
                    username="admin",
                    password=hashed_password,
                    role="Supplier"
                )
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info("Default admin user created: admin/admin123")
                
    except Exception as e:
        app.logger.error(f"Database initialization failed: {str(e)}")
        raise


# ==================== APPLICATION STARTUP ====================
@app.before_request
def init_supplier_inventory():
    """Initialize supplier inventory on first request if needed"""
    try:
        suppliers = User.query.filter_by(role="Supplier").all()
        inventory_created = False
        
        for sup in suppliers:
            if not InventoryConfig.query.filter_by(supplier_id=sup.id).first():
                inv = InventoryConfig(supplier_id=sup.id, flc_stock=100)
                db.session.add(inv)
                inventory_created = True
        
        if inventory_created:
            db.session.commit()
            app.logger.info("Supplier inventory initialized")
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error initializing supplier inventory: {str(e)}")


# ==================== DATABASE EVENT HANDLERS ====================
# @event.listens_for(db.engine, "connect")
# def set_sqlite_pragma(dbapi_connection, connection_record):
#     """Enable foreign key constraints for SQLite"""
#     if 'sqlite' in str(dbapi_connection):
#         cursor = dbapi_connection.cursor()
#         cursor.execute("PRAGMA foreign_keys=ON")
#         cursor.close()


# ==================== UTILITY FUNCTIONS ====================
def sanitize_input(text, max_length=500):
    """Basic input sanitization"""
    if not text:
        return text
    # Remove potentially dangerous characters but allow international characters
    sanitized = re.sub(r'[<>&"\'\\]', '', str(text))
    return sanitized[:max_length]


def validate_quantity(qty_str, field_name="Quantity"):
    """Validate and convert quantity input"""
    try:
        qty = int(qty_str)
        if qty < 0:
            raise ValueError(f"{field_name} cannot be negative")
        return qty
    except (ValueError, TypeError):
        raise ValueError(f"Invalid {field_name}: must be a positive integer")


# ==================== MAIN EXECUTION ====================
if __name__ == "__main__":
    # Fix database URL for Railway
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    
    # Initialize database
    with app.app_context():
        init_db()
    
    # Railway configuration
    port = int(os.environ.get("PORT", 5000))
    is_production = os.environ.get("FLASK_ENV") == "production"
    
    app.run(host='0.0.0.0', port=port, debug=not is_production)

