from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.sql import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)  # ✅ Initialisation correcte

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client')

    # Relation avec la table ScanResult
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}, Role {self.role}>"

    def set_password(self, password):
        """Hash le mot de passe et l'enregistre dans la base de données."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Vérifie si le mot de passe correspond au hachage."""
        return check_password_hash(self.password_hash, password)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hostname = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    machine_type = db.Column(db.String(50), nullable=False)
    os = db.Column(db.String(500), nullable=True)
    wan_latency = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, server_default=func.now(), nullable=False)

    # Relations avec Port et Vulnerability
    ports = db.relationship('Port', backref='scan_result', lazy=True, cascade="all, delete-orphan")
    vulnerabilities = db.relationship('Vulnerability', backref='scan_result', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanResult {self.hostname}, User {self.user_id}>"

class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    port_info = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<Port {self.port_info}, Scan ID {self.scan_id}>"

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    vulnerability_info = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<Vulnerability {self.vulnerability_info}, Scan ID {self.scan_id}>"

if __name__ == "__main__":
    with app.app_context():  # ✅ Ajout du contexte Flask
        db.create_all()
        print("✅ Base de données initialisée !")
    
    app.run(host='0.0.0.0', port=5000)
