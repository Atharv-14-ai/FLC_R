# add_supplier.py
from app import app, db, User, bcrypt
from datetime import datetime

USERNAME = "Supplier"
PLAINTEXT = "123"   # <-- as you asked: password = 123

with app.app_context():
    db.create_all()  # safe: creates missing tables only

    existing = User.query.filter_by(username=USERNAME).first()
    if existing:
        print("User already exists. Updating password for:", USERNAME)
        existing.password = bcrypt.generate_password_hash(PLAINTEXT).decode('utf-8')
        existing.role = 'Supplier'
        existing.created_at = existing.created_at or datetime.utcnow()
        db.session.commit()
        print("✅ Password updated for", USERNAME)
    else:
        hashed = bcrypt.generate_password_hash(PLAINTEXT).decode('utf-8')
        u = User(username=USERNAME, password=hashed, role='Supplier', created_at=datetime.utcnow())
        db.session.add(u)
        db.session.commit()
        print("✅ Supplier created: Username=", USERNAME, " Password=", PLAINTEXT)
