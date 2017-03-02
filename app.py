#!/usr/bin/python
#-*- coding: utf-8 -*-


##########################################################################
"""
    Application created while learning Flask using their blog tutorial   
                           bx0 ( Lucas Nunes )
                                                                       """
##########################################################################

import datetime
import functools
import os
import re
import urllib
from hashlib import md5

from flask import (Flask, flash, Markup, redirect,
                   render_template, request, Response, session, url_for, g)
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_required, \
    login_user, logout_user, current_user

from flask_wtf.csrf import CSRFProtect, CSRFError

from markdown import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.extra import ExtraExtension

from micawber import bootstrap_basic, parse_html
from micawber.cache import Cache as OEmbedCache

from peewee import *

from playhouse.flask_utils import FlaskDB, get_object_or_404, object_list
from playhouse.sqlite_ext import *


"""
 Blog configuration values.
 Edit config.cfg file
"""

#############################################################################

APP_DIR = os.path.dirname(os.path.realpath(__file__))

"""
The playhouse.flask_utils.FlaskDB object 
accepts database URL configuration. 
"""
DATABASE = 'sqliteext:///%s' % os.path.join(APP_DIR, 'app.db')
DEBUG = False

"""
This is used by micawber, which will attempt to generate rich media
embedded objects with maxwidth=800.
"""
SITE_WIDTH = 800

""" Create a Flask WSGI app and configure it using values from the module. """
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile('config.cfg')

"""
FlaskDB is a wrapper for a peewee database that sets up pre/post-request
hooks for managing database connections.
"""
flask_db = FlaskDB(app)

"""
The `database` is the actual peewee database, as opposed to flask_db which is
the wrapper.
"""
database = flask_db.database

"""
Configure micawber with the default OEmbed providers (YouTube, Flickr, etc).
We'll use a simple in-memory cache so that multiple requests for the same
video don't require multiple network requests.
"""
oembed_providers = bootstrap_basic(OEmbedCache())

"""
Flask-Bcrypt is a Flask extension that provides bcrypt hashing utilities for your application.
https://flask-bcrypt.readthedocs.io/en/latest/
"""
bcrypt = Bcrypt(app)

"""
Flask-Login provides user session management for Flask. It handles the common tasks of logging in, logging out,
and remembering your users’ sessions over extended periods of time.
https://flask-login.readthedocs.io/en/latest/ 
"""
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

"""
CSRF Protection 
http://flask-wtf.readthedocs.io/en/stable/csrf.html
"""
csrf = CSRFProtect(app)
# Selectively calling protect() only POST requests
WTF_CSRF_CHECK_DEFAULT = False
######################################
##              MODELS              ##
######################################


# -------------------------------------------------------------------------
#
#    User model
#
#-------------------------------------------------------------------------


class User(flask_db.Model, UserMixin):
    username = CharField(unique=True)
    name = CharField()
    email = CharField(unique=True, index=True)
    password = CharField(max_length=255)
    authenticated = BooleanField(index=True)
    timestamp = DateTimeField(default=datetime.datetime.now, index=True)

    def avatar(self, size):
        """ Get users avatar from gravatar using email """
        return 'http://www.gravatar.com/avatar/%s?d=mm&s=%d' % \
            (md5(self.email.encode('utf-8')).hexdigest(), size)

    def get_id(self):
        """ Return the email address to satisfy Flask-Login's requirements  """
        return self.email

# -------------------------------------------------------------------------
#
#    Entry model
#
#-------------------------------------------------------------------------


class Entry(flask_db.Model):
    title = CharField()
    slug = CharField(unique=True)
    content = TextField()
    published = BooleanField(index=True)
    private = BooleanField(index=False)
    user = ForeignKeyField(User, related_name='authors')
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
        """ Query the Entry database for public Entries only """
        return Entry.select().where(Entry.published == True,
                                    Entry.private == False)

    @classmethod
    def drafts(cls):
        """ Query the Entry database for draft Entries only """
        return Entry.select().where(Entry.published == False,
                                    Entry.private == False)

    @classmethod
    def author(cls, username):
        """
        Query the Entry database for public Entries only
        of the auhor <username>
         """
        user = User.select().where(User.username == username).first()
        return Entry.select().where(Entry.published == True,
                                    Entry.private == False,
                                    Entry.user_id == user.id)

    @classmethod
    def privates(cls):
        """ 
        Query the Entry database for private Entries only
        of the current user
        """
        return Entry.select().where(Entry.user_id == current_user.id,
                                    Entry.private == True)

    @classmethod
    def search(cls, query):
        """ Split and strip all words from query """
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
                    (Entry.private == False) &
                    (FTSEntry.match(search)))
                .order_by(SQL('score').desc()))

    def get_user(self, user_id):
        """ Query User db for user info """
        return User.select().where(User.id == user_id).first()


class FTSEntry(FTSModel):
    entry_id = IntegerField(Entry)
    content = TextField()

    class Meta:
        database = database

# ------------------------------------------------------------------------
#
#    Anonymous only access function
#
#-------------------------------------------------------------------------


def anonymous_required(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        if not session.get('logged_in') or not current_user:
            """ Check if user is a guest """
            return fn(*args, **kwargs)
        return redirect(url_for('account'))
    return inner


######################################
##              ROUTES              ##
######################################

# ------------------------------------------------------------------------
#
#    Register page
#
#-------------------------------------------------------------------------


@app.route('/register/', methods=['GET', 'POST'])
@anonymous_required
def register():
    if request.method == 'POST':
        if request.form.get('username') == '' \
                and request.form.get('name') == '' \
                and request.form.get('email') == '' \
                and request.form.get('password') == '':
            """ Check all the fields are filled """
            flash('Please fill all the fields.', 'danger')
            return redirect(url_for('register'))

        if len(request.form.get('password')) < 6:
            """ Check if password length is less than 6 """
            flash('Your password is too small. 6 characters minimal.',
                  'danger')
            return redirect(url_for('register'))

        if not request.form.get('password') == \
                request.form.get('confirm-password'):
            """ Check all the password fields match """
            flash('Your password don\'t match the confirm password.', 'danger')
            return redirect(url_for('register'))

        user = User
        try:
            """ Try to add user to db """
            with database.atomic():
                user.create(
                    username=request.form.get('username'),
                    name=request.form.get('name'),
                    email=request.form.get('email'),
                    password=bcrypt.generate_password_hash(
                        request.form.get('password')),
                    authenticated=False)
        except:
            flash('Error: This username already exist.', 'danger')
        else:
            flash('Account created successfully.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

#-------------------------------------------------------------------------
#
#    Login page
#
#-------------------------------------------------------------------------


@app.route('/login/', methods=['GET', 'POST'])
@anonymous_required
def login():
    """ Login """
    next_url = request.args.get('next') or request.form.get('next')

    if request.method == 'POST':
        if not request.form.get('password') and \
                not request.form.get('username'):
            """ If login form fields are empty """
            flash('Username and password are required.', 'danger')
            redirect(url_for('login'))

        password = request.form.get('password')
        username = request.form.get('username')

        if User.select().where(User.username == username):
            """ Check if user exists """
            registered_user = User.select().where(
                User.username == username).first()
            if bcrypt.check_password_hash(registered_user.password, password):
                """ Check if user password is correct """
                login_user(registered_user, remember=True)
                registered_user.authenticated = True
                registered_user.save()
                print('%s has logged in' % current_user.name)
                session['logged_in'] = True
                session.permanent = True  # Use cookie to store session.
                flash('You are now logged in.', 'success')
                return redirect(next_url or url_for('index'))
            else:
                flash('Incorrect password.', 'danger')
                redirect(url_for('login'))
        else:
            flash('User don\' exist.', 'danger')
            redirect(url_for('login'))

    return render_template('login.html', next_url=next_url)

# #-------------------------------------------------------------------------
#
#    Logout page
#
#-------------------------------------------------------------------------


@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        try:
            """ Try to change the authenticated value of user to False """
            user = current_user
            user.authenticated = False
            user.save()
            print('%s has logged out' % current_user.name)
        except:
            flash('Error: couldn\'t log out user.', 'danger')
        else:
            session.clear()
            logout_user()
            return redirect(url_for('login'))
    return render_template('logout.html')

# #-------------------------------------------------------------------------
#
#    Account page
#
#-------------------------------------------------------------------------


@app.route('/account/', methods=['GET', 'POST'])
@login_required
def account():
    user = current_user
    if request.method == 'POST':

        if not request.form.get('password'):
            """ Check if field password is filled """
            flash('The actual password is required for any changes.', 'danger')
            return redirect(url_for('account'))

        check_password = User.select().where(
            User.email == current_user.email).first()

        if bcrypt.check_password_hash(check_password.password,
                                      request.form.get('password')):

            user.name = request.form.get('name')

            if not request.form.get('new-password') == '' and \
                    not request.form.get('confirm-new-password') == '' \
                    or request.form.get('new-password') \
                    and not request.form.get('confirm-new-password'):
                """ Check all the password fields are filled """
                if not request.form.get('new-password') == \
                        request.form.get('confirm-new-password'):
                    """ Check all the password fields match """
                    flash('Your new password doesn\'t match \
                        confirm new password.', 'danger')
                    return redirect(url_for('account'))

                if len(request.form.get('new-password')) > 6:
                    """ Check if password length is higher than 6 """
                    user.password = bcrypt.generate_password_hash(
                        request.form.get('new-password'))
                else:
                    flash('Your new password is too small. \
                        6 characters minimum.', 'danger')
                    return redirect(url_for('account'))
            try:
                with database.atomic():
                    user.save()
            except:
                flash('Error: couldn\'t save your profile.', 'danger')
            else:
                flash('Account profile saved successfuly.', 'success')
                return redirect(url_for('account'))
        else:
            flash('Your actual password is not correct.', 'danger')
            return redirect(url_for('account'))

    return render_template('account.html', user=user)

# #-------------------------------------------------------------------------
#
#    Index page
#
#-------------------------------------------------------------------------


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
    return object_list('index.html', query,
                       search=search_query, check_bounds=False)
# -------------------------------------------------------------------------
#
#    Create entry page
#
#-------------------------------------------------------------------------


@app.route('/create/', methods=['GET', 'POST'])
@login_required
def create():
    return _create_or_edit(Entry(title='', content=''), 'create.html')

# -------------------------------------------------------------------------
#
#    Drafts page
#
#-------------------------------------------------------------------------


@app.route('/drafts/')
@login_required
def drafts():
    query = Entry.drafts().order_by(Entry.timestamp.desc())
    return object_list('index.html', query, drafts=1, check_bounds=False)

# -------------------------------------------------------------------------
#
#    Private page
#
#-------------------------------------------------------------------------


@app.route('/private/')
@login_required
def privates():
    query = Entry.privates().order_by(Entry.timestamp.desc())
    return object_list('index.html', query, privates=1, check_bounds=False)

# -------------------------------------------------------------------------
#
#    Profile entries page
#
#-------------------------------------------------------------------------


@app.route('/profile/<username>')
def profile(username):
    query = Entry.author(username).order_by(Entry.timestamp.desc())
    return object_list('index.html', query,
                       profile=username, check_bounds=False)

# -------------------------------------------------------------------------
#
#    Detail page
#
#-------------------------------------------------------------------------


@app.route('/<slug>/')
def detail(slug):
    if session.get('logged_in'):
        query = Entry.select()
    else:
        query = Entry.public()
    entry = get_object_or_404(query, Entry.slug == slug)
    check = Entry.select().where(Entry.slug == slug).first()
    if check.private:
        """
        Check if detailed page is private,
        if so check if the user is the owner
        """
        check_owner = Entry.select().where(
            Entry.user_id == current_user.id, Entry.slug == slug)
        if check_owner:
            return render_template('detail.html', private=1, entry=entry)
        else:
            flash(
                'You\'re not allowed to see private entries \
                 from others.', 'danger')
            return redirect(url_for('privates'))
    else:
        return render_template('detail.html', public=1, entry=entry)

# -------------------------------------------------------------------------
#
#    Edit page
#
#-------------------------------------------------------------------------


@app.route('/<slug>/edit/', methods=['GET', 'POST'])
@login_required
def edit(slug):
    entry = get_object_or_404(Entry, Entry.slug == slug)
    check = Entry.select().where(Entry.slug == slug).first()
    if check.private:
        """
        Check if detailed page is private,
        if so check if the user is the owner
        """
        check_owner = Entry.select().where(
            Entry.user_id == current_user.id, Entry.slug == slug)
        if check_owner:
            return _create_or_edit(entry, 'edit.html')
        else:
            flash(
                'You\'re not allowed to see private \
                entries from others.', 'danger')
            return redirect(url_for('privates'))
    return _create_or_edit(entry, 'edit.html')

# -------------------------------------------------------------------------
#
#    Delete page
#
#-------------------------------------------------------------------------


@app.route('/<slug>/delete/', methods=['GET', 'POST'])
@login_required
def delete(slug):
    entry = get_object_or_404(Entry.select(), Entry.slug == slug)
    check = Entry.select().where(Entry.slug == slug).first()
    if check.private:
        """
        Check if detailed page is private,
        if so check if the user is the owner
        """
        check_owner = Entry.select().where(
            Entry.user_id == current_user.id, Entry.slug == slug)
        if check_owner:
            return render_template('detail.html', entry=entry)
        else:
            flash(
                'You\'re not allowed to see private \
                 entries from others.', 'danger')
            return redirect(url_for('privates'))

    if request.method == 'POST':
        if not entry:
            flash('This entry don\' exist.', 'danger')
        else:
            if check.private:
                """
                Check if detailed page is private,
                if so check if the user is the owner
                """
                check_owner = Entry.select().where(
                    Entry.user_id == current_user.id, Entry.slug == slug)
                if not check_owner:
                    flash(
                        'You\'re not allowed to see private \
                         entries from others.', 'danger')
                    return redirect(url_for('privates'))

            try:
                with database.atomic():
                    entry.delete_instance()
            except IntegrityError:
                flash('Error: this entry don\' exist.', 'danger')
            else:
                flash('Entry deleted successfully.', 'success')
                return redirect(url_for('index'))

    return render_template('delete.html', entry=entry)


######################################
##             FUNCTIONS            ##
######################################

@login_manager.user_loader
def user_loader(user_id):
    """
    Given *user_id*, return the associated User object.
    :param unicode user_id: user_id (email) user to retrieve
    """
    return User.get(email=user_id)


def _create_or_edit(entry, template):
    """ Function called on Create and Edit pages """
    if request.method == 'POST':
        entry.title = request.form.get('title') or ''
        entry.content = request.form.get('content') or ''
        entry.published = request.form.get('published') or False
        entry.private = request.form.get('private') or False
        entry.user_id = current_user.id
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


@app.before_request
def csrf_protect():
    if request.method == "POST":
        csrf.protect()


######################################
##      TEMPLATES CUSTOM TAGS       ##
######################################

# Pluralize template custom tag
@app.template_filter('pluralize')
def pluralize(number, singular='', plural='s'):
    """ Will give the singular or plural state of a word with you 
    setting those based on the length of the variable """
    if number == 1:
        return singular
    else:
        return plural

# Clean query string template tag


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


######################################
##              ERRORS              ##
######################################

@app.errorhandler(404)
def not_found(exc):
    return render_template('errors/404.html')


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('errors/404.html',
                           title="Error: CSRF token",
                           message=e.description)


######################################
##           Initialization         ##
######################################

def main():
    database.create_tables([User, Entry, FTSEntry], safe=True)
    app.run(host='0.0.0.0', debug=True, port=app.config['PORT'])

if __name__ == '__main__':
    main()
