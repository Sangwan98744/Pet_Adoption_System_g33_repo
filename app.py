import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pets.db'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_shelter = db.Column(db.Boolean, default=False)
    pets = db.relationship('Pet', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Pet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    species = db.Column(db.String(50), nullable=False)
    breed = db.Column(db.String(50))
    age = db.Column(db.Integer)
    description = db.Column(db.Text)
    image_filename = db.Column(db.String(200))  # Changed from image_url
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    adoption_requests = db.relationship('AdoptionRequest', backref='pet', lazy=True)

class AdoptionRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pet_id = db.Column(db.Integer, db.ForeignKey('pet.id'), nullable=False)
    message = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    pets = Pet.query.order_by(Pet.created_at.desc()).paginate(page=page, per_page=12)
    total_pets = Pet.query.count()
    app.logger.info(f"Total pets in database: {total_pets}")
    return render_template('index.html', pets=pets, total_pets=total_pets)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/search')
def search():
    query = request.args.get('query', '')
    species = request.args.get('species', '')
    breed = request.args.get('breed', '')
    
    pets = Pet.query
    if query:
        pets = pets.filter(Pet.name.ilike(f'%{query}%'))
    if species:
        pets = pets.filter(Pet.species == species)
    if breed:
        pets = pets.filter(Pet.breed.ilike(f'%{breed}%'))
    
    return render_template('search.html', pets=pets.all())

@app.route('/pet/<int:id>')
def pet_detail(id):
    pet = Pet.query.get_or_404(id)
    return render_template('pet_detail.html', pet=pet)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/pet/create', methods=['GET', 'POST'])
@login_required
def create_pet():
    if not current_user.is_shelter:
        flash('Only shelters can create pet listings')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            if 'image' not in request.files:
                raise ValueError('No file part')
            file = request.files['image']
            if file.filename == '':
                raise ValueError('No selected file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                pet = Pet(
                    name=request.form['name'],
                    species=request.form['species'],
                    breed=request.form['breed'],
                    age=int(request.form['age']),
                    description=request.form['description'],
                    image_filename=filename,
                    owner_id=current_user.id
                )
                db.session.add(pet)
                db.session.commit()
                app.logger.info(f"Pet created: {pet.id} - {pet.name}")
                flash('Pet added successfully!')
                return redirect(url_for('pet_detail', id=pet.id))
            else:
                raise ValueError('Invalid file type')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating pet: {str(e)}")
            flash(f'Error creating pet: {str(e)}')
            return redirect(url_for('create_pet'))
    
    return render_template('create_pet.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'])
        new_user = User(username=request.form['username'], 
                        email=request.form['email'], 
                        password_hash=hashed_password,
                        is_shelter=request.form.get('is_shelter') == 'on')
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/pet/<int:id>/adopt', methods=['POST'])
@login_required
def adopt_pet(id):
    # pet = Pet.query.get_or_404(id)
    # if current_user.is_shelter:
    #     flash('Shelters cannot submit adoption requests')
    #     return redirect(url_for('pet_detail', id=id))
    
    # existing_request = AdoptionRequest.query.filter_by(pet_id=id, user_id=current_user.id).first()
    # if existing_request:
    #     flash('You have already submitted an adoption request for this pet')
    #     return redirect(url_for('pet_detail', id=id))
    
    # new_request = AdoptionRequest(pet_id=id, user_id=current_user.id, message=request.form['message'])
    # db.session.add(new_request)
    # db.session.commit()
    # flash('Your adoption request has been submitted')
    # return redirect(url_for('pet_detail', id=id))
    return redirect(url_for('index'))

@app.route('/pet/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_pet(id):
    pet = Pet.query.get_or_404(id)
    if pet.owner_id != current_user.id:
        flash('You can only edit your own pet listings')
        return redirect(url_for('pet_detail', id=id))
    
    if request.method == 'POST':
        pet.name = request.form['name']
        pet.species = request.form['species']
        pet.breed = request.form['breed']
        pet.age = request.form['age']
        pet.description = request.form['description']
        
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                pet.image_filename = filename
        
        db.session.commit()
        return redirect(url_for('pet_detail', id=id))
    
    return render_template('edit_pet.html', pet=pet)

@app.route('/debug/pets')
def debug_pets():
    pets = Pet.query.all()
    return jsonify([{
        'id': pet.id,
        'name': pet.name,
        'species': pet.species,
        'breed': pet.breed,
        'age': pet.age,
        'owner_id': pet.owner_id
    } for pet in pets])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

