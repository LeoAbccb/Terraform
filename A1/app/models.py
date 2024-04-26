
from datetime import datetime, timedelta, timezone
from hashlib import md5
from app import app, db, login
import jwt

from flask_login import UserMixin

from werkzeug.security import generate_password_hash, check_password_hash


class Follow(db.Model):
    __tablename__ = 'followers'
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    username = db.Column(db.String(64), index=True)
    follow_date = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_type = db.Column(db.String(100))
    followed = db.relationship(
        'User', secondary=Follow.__tablename__,
        primaryjoin=(Follow.follower_id == id),
        secondaryjoin=(Follow.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def __repr__(self) -> str:
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode("utf-8")).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def follow(self, user):
        if not self.is_following(user):
            follow = Follow(follower_id=self.id, followed_id=user.id)
            db.session.add(follow)
            db.session.commit()

    def unfollow(self, user):
        if self.is_following(user):
            Follow.query.filter_by(follower_id=self.id, followed_id=user.id).delete()
            db.session.commit()

    def is_following(self, user):
        return self.followed.filter(Follow.followed_id == user.id).count() > 0

    def followed_posts(self):
        followed = Post.query.join(
            Follow, Follow.followed_id == Post.user_id
        ).filter(Follow.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode({"reset_password": self.id,
                           "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)},
                          app.config["SECRET_KEY"], algorithm="HS256")

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")[
                "reset_password"]
        except:
            return None
        return User.query.get(id)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self) -> str:
        return f'<Post {self.body}>'

class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_web = db.Column(db.String(1000))
    link_p = db.Column(db.String(1000))
    title = db.Column(db.String(1000))
    type = db.Column(db.String(1000))

class detail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_photo = db.Column(db.String(1000))
    menu_p = db.Column(db.String(1000))
    info = db.Column(db.String(1000))

class book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    time = db.Column(db.String(1000))
    people = db.Column(db.String(1000), nullable=False)
