from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

# Upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# MODELS ---------------------------------------------------

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    admin = db.relationship('Admin', backref='agents')


# ROUTES ---------------------------------------------------

@app.route('/')
def home():
    return "Flask Admin-Agent App Running"


# Admin Signup
@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if Admin.query.filter_by(username=username).first():
            return "Admin already exists"

        new_admin = Admin(username=username, password=password)
        db.session.add(new_admin)
        db.session.commit()
        return redirect(url_for('admin_login'))

    return render_template("admin_signup.html")


# Admin Login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect(url_for("admin_upload"))

        return "Invalid credentials"

    return render_template("admin_login.html")


# Agent Signup
@app.route('/agent/signup', methods=['GET','POST'])
def agent_signup():
    admins = Admin.query.all()

    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        admin_id = request.form['admin_id']

        new_agent = Agent(username=username, password=password, admin_id=admin_id)
        db.session.add(new_agent)
        db.session.commit()
        return redirect(url_for('agent_login'))

    return render_template("agent_signup.html", admins=admins)


# Agent Login
@app.route('/agent/login', methods=['GET','POST'])
def agent_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        agent = Agent.query.filter_by(username=username).first()
        if agent and check_password_hash(agent.password, password):
            session['agent_id'] = agent.id
            session['admin_id'] = agent.admin_id
            return "Agent logged in"

        return "Invalid credentials"

    return render_template("agent_login.html")


# Admin Upload
@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload():
    if 'admin_id' not in session:
        return "Unauthorized"

    if request.method == 'POST':
        file = request.files.get('document')
        if not file:
            return "No file uploaded"

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        return f"File {filename} uploaded successfully"

    return render_template("admin_upload.html")

# Admin: View My Agents
@app.route('/admin/agents')
def view_agents():
    # 1. Security check: Ensure admin is logged in
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    # 2. Fetch the current admin object
    current_admin = Admin.query.get(session['admin_id'])
    
    # 3. Get the agents using the relationship defined in your model
    # 'current_admin.agents' works because of backref='agents' in the Agent model
    my_agents = current_admin.agents 

    return render_template("admin_agents.html", agents=my_agents, admin=current_admin)

# Agent Query (stub)
@app.route('/agent/query', methods=['POST'])
def agent_query():
    if 'agent_id' not in session:
        return "Unauthorized"

    agent = Agent.query.get(session['agent_id'])
    admin_id = request.form.get('admin_id')

    if str(agent.admin_id) != str(admin_id):
        return "Access denied: not your admin"

    return "Query sent (placeholder)"


# RUN APP ---------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
