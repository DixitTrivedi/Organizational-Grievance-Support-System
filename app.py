from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grievances.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# SQLAlchemy models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Grievance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    grievance_type = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    department = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='Pending')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({'message': 'Logged in successfully', 'role': user.role}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/grievance', methods=['POST'])
@login_required
def submit_grievance():
    data = request.get_json()
    new_grievance = Grievance(
        user_id=current_user.id,
        grievance_type=data['grievance_type'],
        description=data['description'],
        department=data['department'],
        severity=data['severity']
    )
    if current_user.role == 'employee':
        # Allow employee to assign grievance to HR or IT during submission
        if data['department'] == 'HR' or data['department'] == 'IT':
            new_grievance.department = data['department']
    db.session.add(new_grievance)
    db.session.commit()
    return jsonify({'message': 'Grievance submitted successfully'}), 200

@app.route('/grievance/<int:grievance_id>', methods=['PUT'])
@login_required
def update_grievance(grievance_id):
    data = request.get_json()
    grievance = Grievance.query.get_or_404(grievance_id)
    
    # Ensure role-based access to update grievance status
    if current_user.role == 'HR' and grievance.department != 'HR':
        return jsonify({'message': 'Unauthorized'}), 403
    elif current_user.role == 'IT' and grievance.department != 'IT':
        return jsonify({'message': 'Unauthorized'}), 403
    
    grievance.status = data['status']
    db.session.commit()
    return jsonify({'message': 'Grievance status updated successfully'}), 200

@app.route('/grievances')
@login_required
def view_grievances():
    print(current_user.role)
    if current_user.role == 'admin':
        grievances = Grievance.query.all()
    elif current_user.role == 'hr':
        print("hr griv")
        grievances = Grievance.query.filter_by(department='HR').all()
    elif current_user.role == 'it':
        grievances = Grievance.query.filter_by(department='IT').all()
    else:
        grievances = Grievance.query.filter_by(user_id=current_user.id).all()
    
    return jsonify([{
        'id': g.id,
        'user_id': g.user_id,
        'grievance_type': g.grievance_type,
        'description': g.description,
        'department': g.department,
        'severity': g.severity,
        'status': g.status
    } for g in grievances]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
