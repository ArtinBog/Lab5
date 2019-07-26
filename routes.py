from flask import Flask, flash, render_template, request, url_for, redirect, jsonify, session
from models import db, User, Post
from forms import SignupForm, LoginForm, NewpostForm
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = "s14a"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/lab_5'

db.init_app(app)

@app.route('/')
@app.route('/index')
def index():
    if 'username' in session:
        session_user = User.query.filter_by(username=session['username']).first()
        posts = Post.query.filter_by(author=session_user.uid).all()
        all_authors = User.query.all()
        return render_template('index.html', title='Home',  User=User, all_authors=all_authors, posts=posts, session_username=session_user.username)

    all_posts = Post.query.all()
    return render_template('index.html', title='Home', User=User, posts=all_posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user is None or not sha256_crypt.verify(password, user.password):
            flash('Invalid credentials. Check your username and/or password')
            return redirect(url_for('login'))

        session['username'] = username
        return redirect(url_for('index'))


    return render_template('login.html', form=form, title='Login')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/newpost', methods=['GET', 'POST'])
def newpost():
    form = NewpostForm()

    if request.method == 'POST':
        session_user = User.query.filter_by(username=session['username']).first()
        content = request.form['content']
        new_post = Post(author=session_user.uid, content=content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))

    else:
        return render_template('newpost.html', title='Newpost', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if request.method=="POST":
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('The username already exists. Please pick another one.')
            return redirect(url_for('signup'))
        user = User(username=username, password=sha256_crypt.hash(password))
        db.session.add(user)
        db.session.commit()
        flash('User: ' + username + ' is added!')
        return redirect('login.html', form=form, title='Sign up')

    return render_template('signup.html', form=form, title='Sign up')



if __name__ == "__main__":
    app.run(debug=True)
