#-*- coding: utf-8 -*-
#################################################################################
#      Application created while learning Flask using their blog tutorial       #
#                                                                               #
#                               bx0 ( Lucas Nunes )                             #
#################################################################################

import datetime
import functools
import os
import re
import urllib

from flask import (Flask, flash, Markup, redirect, render_template, request,
                   Response, session, url_for)
from flask_bcrypt import Bcrypt
from flask.ext.login import LoginManager, UserMixin, \
                                login_required, login_user, logout_user 

from markdown import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.extra import ExtraExtension

from micawber import bootstrap_basic, parse_html
from micawber.cache import Cache as OEmbedCache

from peewee import *

from playhouse.flask_utils import FlaskDB, get_object_or_404, object_list
from playhouse.sqlite_ext import *


# Blog configuration values.
# Edit config.cfg file

#############################################################################

APP_DIR = os.path.dirname(os.path.realpath(__file__))

# The playhouse.flask_utils.FlaskDB object accepts database URL configuration.
DATABASE = 'sqliteext:///%s' % os.path.join(APP_DIR, 'blog.db')
DEBUG = False

# The secret key is used internally by Flask to encrypt session data stored
# in cookies. Make this unique for your app.
SECRET_KEY = 'shhh, secret!'

# This is used by micawber, which will attempt to generate rich media
# embedded objects with maxwidth=800.
SITE_WIDTH = 800

# Create a Flask WSGI app and configure it using values from the module.
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile('config.cfg')

# FlaskDB is a wrapper for a peewee database that sets up pre/post-request
# hooks for managing database connections.
flask_db = FlaskDB(app)

# The `database` is the actual peewee database, as opposed to flask_db which is
# the wrapper.
database = flask_db.database

# Configure micawber with the default OEmbed providers (YouTube, Flickr, etc).
# We'll use a simple in-memory cache so that multiple requests for the same
# video don't require multiple network requests.
oembed_providers = bootstrap_basic(OEmbedCache())

# Flask-Bcrypt is a Flask extension that provides bcrypt hashing utilities for your application.
# https://flask-bcrypt.readthedocs.io/en/latest/
bcrypt = Bcrypt(app)

# Flask-Login provides user session management for Flask. It handles the common tasks of logging in, logging out, 
# and remembering your users’ sessions over extended periods of time.
# https://flask-login.readthedocs.io/en/latest/
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(flask_db.Model):
    username = CharField(unique=True)
    email = CharField(unique=True, index=True)
    password = CharField()
    authenticated = BooleanField(index=True)

    def is_active(self):
        """ True, as all users are active """
        return True

    def get_id(self):
        """ Return the email address to satisfy Flask-Login's requirements  """
        return self.email

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

class Entry(flask_db.Model):
    title = CharField()
    slug = CharField(unique=True)
    content = TextField()
    published = BooleanField(index=True)
    timestamp = DateTimeField(default=datetime.datetime.now, index=True)

    @property
    def html_content(self):
        """
        Generate HTML representation of the markdown-formatted blog entry,
        and also convert any media URLs into rich media objects such as video
        players or images.
        """
        hilite = CodeHiliteExtension(linenums=False, css_class='highlight')
        extras = ExtraExtension()
        markdown_content = markdown(self.content, extensions=[hilite, extras])
        oembed_content = parse_html(
            markdown_content,
            oembed_providers,
            urlize_all=True,
            maxwidth=app.config['SITE_WIDTH'])
        return Markup(oembed_content)

    def save(self, *args, **kwargs):
        # Generate a URL-friendly representation of the entry's title.
        if not self.slug:
            self.slug = re.sub('[^\w]+', '-', self.title.lower()).strip('-')
        ret = super(Entry, self).save(*args, **kwargs)

        # Store search content.
        self.update_search_index()
        return ret

    def update_search_index(self):
        # Create a row in the FTSEntry table with the post content. This will
        # allow us to use SQLite's awesome full-text search extension to
        # search our entries.
        query = (FTSEntry
                 .select(FTSEntry.docid, FTSEntry.entry_id)
                 .where(FTSEntry.entry_id == self.id))
        try:
            fts_entry = query.get()
        except FTSEntry.DoesNotExist:
            fts_entry = FTSEntry(entry_id=self.id)
            force_insert = True
        else:
            force_insert = False
        fts_entry.content = '\n'.join((self.title, self.content))
        fts_entry.save(force_insert=force_insert)

    @classmethod
    def public(cls):
        return Entry.select().where(Entry.published == True)

    @classmethod
    def drafts(cls):
        return Entry.select().where(Entry.published == False)

    @classmethod
    def search(cls, query):
        words = [word.strip() for word in query.split() if word.strip()]
        if not words:
            # Return an empty query.
            return Entry.select().where(Entry.id == 0)
        else:
            search = ' '.join(words)

        # Query the full-text search index for entries matching the given
        # search query, then join the actual Entry data on the matching
        # search result.
        return (FTSEntry
                .select(
                    FTSEntry,
                    Entry,
                    FTSEntry.rank().alias('score'))
                .join(Entry, on=(FTSEntry.entry_id == Entry.id).alias('entry'))
                .where(
                    (Entry.published == True) &
                    (FTSEntry.match(search)))
                .order_by(SQL('score').desc()))

class FTSEntry(FTSModel):
    entry_id = IntegerField(Entry)
    content = TextField()

    class Meta:
        database = database

# def login_required(fn):
#     @functools.wraps(fn)
#     def inner(*args, **kwargs):
#         if session.get('logged_in'):
#             return fn(*args, **kwargs)
#         return redirect(url_for('login', next=request.path))
#     return inner

@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and request.form.get('username') and request.form.get('email') and request.form.get('password'):
        if request.form.get('password') == request.form.get('confirm-password'):
            user = User
            user.username = request.form.get('username')
            user.email = request.form.get('email')
            user.password = bcrypt.generate_password_hash(request.form.get('password'))
            user.authenticated = True
            try:
                with database.atomic():
                    user.save()
            except IntegrityError:
                flash('Error: this user is already exist.', 'danger')
            else:
                flash('Account saved successfully.', 'success')
                return redirect(url_for('index'))
        else:
            flash('Your password don\'t match the confirm password.', 'danger')
    else:
        flash('Please fill all the fields.', 'danger')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or request.form.get('next')
    if request.method == 'POST' and request.form.get('password') and request.form.get('username'):
        password = bcrypt.generate_password_hash(request.form.get('password'))
        username = request.form.get('username')
        user = User.get_object_or_404(User.select(), User.username == username)
        if bcrypt.check_password_hash(password, user.password):
            login_user(user.id)
            # session['logged_in'] = True
            # session.permanent = True  # Use cookie to store session.
            flash('You are now logged in.', 'success')
            return redirect(next_url or url_for('index'))
        else:
            flash('Incorrect username/password.', 'danger')
    return render_template('login.html', next_url=next_url)

@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        user = current_user
        user.authenticated = False
        session.clear()
        logout_user()
        return redirect(url_for('login'))
    return render_template('logout.html')

@app.route('/')
def index():
    search_query = request.args.get('q')
    if search_query:
        query = Entry.search(search_query)
    else:
        query = Entry.public().order_by(Entry.timestamp.desc())

    # The `object_list` helper will take a base query and then handle
    # paginating the results if there are more than 20. For more info see
    # the docs:
    # http://docs.peewee-orm.com/en/latest/peewee/playhouse.html#object_list
    return object_list(
        'index.html',
        query,
        search=search_query,
        check_bounds=False)

def _create_or_edit(entry, template):
    if request.method == 'POST':
        entry.title = request.form.get('title') or ''
        entry.content = request.form.get('content') or ''
        entry.published = request.form.get('published') or False
        if not (entry.title and entry.content):
            flash('Title and Content are required.', 'danger')
        else:
            # Wrap the call to save in a transaction so we can roll it back
            # cleanly in the event of an integrity error.
            try:
                with database.atomic():
                    entry.save()
            except IntegrityError:
                flash('Error: this title is already in use.', 'danger')
            else:
                flash('Entry saved successfully.', 'success')
                if entry.published:
                    return redirect(url_for('detail', slug=entry.slug))
                else:
                    return redirect(url_for('edit', slug=entry.slug))

    return render_template(template, entry=entry)

@app.route('/create/', methods=['GET', 'POST'])
@login_required
def create():
    return _create_or_edit(Entry(title='', content=''), 'create.html')

@app.route('/drafts/')
@login_required
def drafts():
    query = Entry.drafts().order_by(Entry.timestamp.desc())
    return object_list('index.html', query, check_bounds=False)

@app.route('/<slug>/')
def detail(slug):
    if session.get('logged_in'):
        query = Entry.select()
    else:
        query = Entry.public()
    entry = get_object_or_404(query, Entry.slug == slug)
    return render_template('detail.html', entry=entry)

@app.route('/<slug>/edit/', methods=['GET', 'POST'])
@login_required
def edit(slug):
    entry = get_object_or_404(Entry, Entry.slug == slug)
    return _create_or_edit(entry, 'edit.html')

@app.route('/<slug>/delete/', methods=['GET', 'POST'])
@login_required
def delete(slug):
    entry = get_object_or_404(Entry.select(), Entry.slug == slug)
    if request.method == 'POST':
        if not entry:
            flash('This entry don\' exist.', 'danger')
        else:
            try:
                with database.atomic():
                    entry.delete_instance()
            except IntegrityError:
                flash('Error: this entry don\' exist.', 'danger')
            else:
                flash('Entry deleted successfully.', 'success')
                return redirect(url_for('index'))

    return render_template('delete.html', entry=entry)

@login_manager.user_loader
def user_loader(user_id):
    """Given *user_id*, return the associated User object.

    :param unicode user_id: user_id (email) user to retrieve
    """
    return User.query.get(user_id)


@app.template_filter('clean_querystring')
def clean_querystring(request_args, *keys_to_remove, **new_values):
    # We'll use this template filter in the pagination include. This filter
    # will take the current URL and allow us to preserve the arguments in the
    # querystring while replacing any that we need to overwrite. For instance
    # if your URL is /?q=search+query&page=2 and we want to preserve the search
    # term but make a link to page 3, this filter will allow us to do that.
    querystring = dict((key, value) for key, value in request_args.items())
    for key in keys_to_remove:
        querystring.pop(key, None)
    querystring.update(new_values)
    return urllib.urlencode(querystring)

@app.errorhandler(404)
def not_found(exc):
    return render_template('404.html')

def main():
    database.create_tables([Entry, FTSEntry], safe=True)
    app.run(host='0.0.0.0', debug=True, port=app.config['PORT'])

if __name__ == '__main__':
    main()