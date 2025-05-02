from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://abc:abc123@localhost/users_db'
app.config['SECRET_KEY'] = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    submitted_at = db.Column(db.DateTime, default=db.func.current_timestamp())


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def flash_with_timestamp(message, category='message'):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    flash(f"[{timestamp}] {message}", category)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash_with_timestamp('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
    except db.exc.IntegrityError as e:
        return render_template('register.html')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash_with_timestamp('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash_with_timestamp('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash_with_timestamp('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    submission_count = Submission.query.filter_by(user_id=user.id).count()
    return render_template('dashboard.html', email=user.email, submission_count=submission_count)


@app.route('/submit', methods=['POST'])
def submit():
    if 'user_id' not in session:
        flash_with_timestamp('Please log in to submit a paper.', 'warning')
        return redirect(url_for('login'))

    title = request.form.get('title')
    if not title:
        flash_with_timestamp('Paper title is required.', 'warning')
        return redirect(url_for('dashboard'))

    if 'paper' not in request.files:
        flash_with_timestamp('No file uploaded.', 'warning')
        return redirect(url_for('dashboard'))

    file = request.files['paper']
    if file.filename == '':
        flash_with_timestamp('No file selected.', 'warning')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        user = User.query.get(session['user_id'])
        email_prefix = user.email.split('@')[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        original_filename = secure_filename(file.filename)
        filename = f"{email_prefix}_{title}_{timestamp}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        submission = Submission(user_id=user.id, title=title, filename=filename)
        db.session.add(submission)
        db.session.commit()

        flash_with_timestamp('Paper submitted successfully!', 'success')
    else:
        flash_with_timestamp('Invalid file type. Only PDF files are allowed.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash_with_timestamp('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000)