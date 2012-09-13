#!/usr/bin/env python

import webapp2
import jinja2
import os
import hmac
import re
import json
import logging
import time

from google.appengine.ext import db
from google.appengine.api import memcache

SECRET='shkan42r'
KEY = 'top'
LAST_QUERY = time.time()
N_KEY = 'new'

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname	   (__file__), 'templates')))


# HASH FUNCTIONS ###########################################

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_hash(s):
    return '%s|%s' %(s, hash_str(s))

def check_hash(h):
    s = h.split('|')[0]
    if h == make_hash(s):
        return s
    else:
        return None

def check_pass(s, HASH):
    if hash_str(s) == HASH:
        return s
    else:
        return False

def getPosts():
    logging.error("DB QUERY")
    posts = db.GqlQuery("SELECT * FROM Post ORDER BY date DESC")

    global LAST_QUERY
    LAST_QUERY = time.time()

    posts = list(posts)
    return posts


def update_cache():
    posts = getPosts()
    memcache.set(KEY, posts)


# SIGN UP FUNCTIONS #############################################

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)


# DATABASE CLASSES ##########################################

class Post(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    date = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty
    created = db.DateTimeProperty(auto_now_add = True)


# PARENT HANDLER CLASS ######################################

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        t = jinja_environment.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def searchUser(self, user):
        key = None
        users = db.GqlQuery("SELECT * FROM User")
        for u in users:
            if user == u.username:
                key = u.key().id()
        return key

    def getName(self):
        return self.request.cookies.get('name').split('|')[0]


    def check_logged(self):
        check = self.request.cookies.get('name')
        if check:
            return check.split('|')[0]
        else:
            return None

    def wiki_logged_msg(self):
        logged_msg = '<a href="/login">Login</a> | <a href="/wiki/signup">Register</a></div>'
        logged = self.check_logged()
        if logged:
            logged_msg = 'Logged in as %s | <a href="/logout">Logout</a>' % logged
        return logged_msg
    

    def get_logged_msg(self):
        #default msg
        logged_msg = '<a href="/login" class = "login-link">Login</a> | <a href="/signup" class = "login-link">Register</a>'

        check = self.request.cookies.get('name')
        if check:
            logged = check.split('|')[0]
            if logged:
                logged_msg = 'Logged in as %s | <a href="/logout" class = "login-link">Logout</a>' % logged
        return logged_msg

class MainHandler(Handler):
    

    def update_visits(self):
        visits = 0
        visits_cookie = self.request.cookies.get('visits')
        if visits_cookie:
            c = check_hash(visits_cookie)
            if c:
                visits = int(c)
        visits += 1

        new_cookie = make_hash(str(visits))
        self.response.headers.add_header('Set-Cookie:','visits=%s' % new_cookie)

        return visits

    def get(self):
        visits = self.update_visits()
        logged_msg = self.get_logged_msg()
        self.render('front.html', visits=visits, logged_msg = logged_msg)    



class BlogHandler(MainHandler):
    def render_front(self, **kw):
        if not memcache.get(KEY):
            update_cache()
        posts = memcache.get(KEY)

        logged_msg = self.get_logged_msg()
        query = time.time() - LAST_QUERY
        self.render('blog.html', posts=posts, logged_msg=logged_msg, query=query)

    def get(self):
        self.render_front()
    
    def post(self):
        self.redirect('/blog/newpost')




        
class NewHandler(MainHandler):
    def render_new(self, **kw):
        logged_msg = self.get_logged_msg()
        self.render('newpost.html', logged_msg = logged_msg, **kw)

    def get(self):
        self.render_new()

    def post(self):
        name = self.request.get('subject')
        content = self.request.get('content')

        if name and content:
            p = Post(name = name, content = content)
            p.put()
            update_cache()

            self.redirect('/blog/%s' % p.key().id())
        else:
            error = "Please provide both name and content"
            self.render_new(error=error, content=content, name=name)



class PermHandler(MainHandler):
    def get(self, blog_id):
        if not memcache.get(blog_id):
            memcache.set(blog_id, (time.time(),Post.get_by_id(int(blog_id))))

        lastquery, s = memcache.get(blog_id)
        query = time.time() - lastquery
        self.render("blog.html", posts=[s], query=query)




class SignUpHandler(MainHandler):

    def get(self):
        self.render('signup.html')

    def post(self):
        users = db.GqlQuery("SELECT username FROM User")
        users = list(users)

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        user_error=""
        pass_error=""
        ver_error=""
        email_error=""

        messup = False

        if not valid_username(username):
            user_error = "Please enter a valid username!"
            messup = True
        if not valid_password(password):
            pass_error = "Please enter a valid password!"
            messup = True
        elif password != verify:
            ver_error = "The two passwords do not match!"
            messup = True
        if email and not valid_email(email):
            email_error = "Please enter a valid email, or leave it out!"
            messup = True
        if self.searchUser(username):
            user_error = "That user is already taken!"
            messup = True

        if not messup:

            user_hash = str(make_hash(username))
            pw_hash = str(hash_str(password))
            self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % user_hash)

            u = User(username= username, password= pw_hash, email = email)
            u.put()

            self.redirect('/')
        else:
            self.render('signup.html', user_error=user_error, pass_error=pass_error, ver_error=ver_error, email_error=email_error)



class LoginHandler(MainHandler):
    def get(self):
        self.render('login.html')
    def post(self):
        username = self.request.get('username')
        password = hash_str(self.request.get('password'))

        e = "Login invalid"
        error = True

        key = self.searchUser(username)

        if key:
            correct = User.get_by_id(key).password
            if correct == password:
                error = False
                self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % str(make_hash(username)))

        if not error:
            self.redirect('/')
        else:
            self.render('login.html', error=e)

class LogoutHandler(MainHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % "")
        self.redirect('/')

class Why(MainHandler):
    def render_why(self, msg="", button_msg="", link=""):
        self.render('why.html', msg= msg, button_msg = button_msg, link = link)

class WhyHoursH(Why):
    def get(self):
        msg = 'Because I spent hours making a login implementation and database!'
        button_msg = 'Why did you spend hours making a login feature?'
        self.render_why(msg = msg, button_msg = button_msg, link= '/whylog')

class WhyLogH(Why):
    def get(self):
        msg = 'So that users would be able to login, obviously!'
        button_msg = 'But why should I bother logging in?!'
        self.render_why(msg=msg, button_msg=button_msg, link='/whyhours')


class JsonHandler(MainHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY date DESC")
        posts = list(posts)

        posts_list = []
        for post in posts:
            post_dict = {}
            post_dict['subject'] = post.name
            post_dict['content'] = post.content
            post_dict['created'] = post.date.strftime('%c')
            posts_list.append(post_dict)

        json_data = json.dumps(posts_list)

        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(json_data)


class PermJsonHandler(MainHandler):
    def get(self, resource):
        post = Post.get_by_id(int(resource))

        post_dict = {}
        post_dict['subject'] = post.name
        post_dict['content'] = post.content
        post_dict['created'] = post.date.strftime('%c')

        json_data = json.dumps(post_dict)

        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(json_data)


class WelcomeHandler(MainHandler):
    def get(self):
        name = self.getName()
        self.response.out.write('<h2> Welcome, %s! </h2>' % name) 

class Flush(MainHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')





# WIKI ##########################################################

PAGE_RE = r'(/(?:[a-zA-Z0-9-]+/?)*)'

class Page(db.Model):
    #path_name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    date = db.DateTimeProperty(auto_now_add = True)


def queryPage(page):
    logging.error('DB QUERY for ' + page)
    page = Page.get_by_key_name(page)
    if page:
        return page.content
    else:
        return None

class MainWiki(MainHandler):
    def get(self):
        logged_msg = self.wiki_logged_msg()
        edit_msg = ''

        content = """
        <h2> Welcome to Z-Wiki! </h2> 
        Go to path you like after /wiki to create or edit a page! <br> <br>
        For example: /wiki/asdf goes to a unisque page. You can edit it if you register and login. <br> <br>
        You can use Z-Wiki to practice your HTML! <br> <br>
        This wiki was created for the Udacity CS253 Course final by <b>Yoav Zimmerman</b>
        """
        self.render('wiki.html', logged_msg=logged_msg, edit_msg=edit_msg, content=content)

class Wiki(MainHandler):
    def get(self, path):
        content = queryPage(path)
        if not content:
            self.redirect('/wiki/_edit%s' % path)

        logged_msg = self.wiki_logged_msg()
        edit_msg = ''

        if self.check_logged():
            edit_msg = '<a href="/wiki/_edit%s">Edit "%s"</a>' % (path,path)

        self.render('wiki.html', logged_msg=logged_msg, edit_msg=edit_msg, content=content)


class Edit(MainHandler):
    def get(self, path):
        logged_msg = self.wiki_logged_msg()

        self.render('edit.html', logged_msg=logged_msg)  

    def post(self, path):

        content = self.request.get('content')
        
        page = Page(key_name=path, content=content)
        page.put()

        self.redirect('/wiki%s' % path)


app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/blog', BlogHandler), 
                   			   ('/blog/newpost', NewHandler),
                   			   ('/blog/(\d+)', PermHandler),
                               ('/wiki/signup', SignUpHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/whyhours', WhyHoursH),
                               ('/whylog', WhyLogH),
                               ('/blog.json', JsonHandler),
                               ('/blog/(\d+).json', PermJsonHandler),
                               ('/blog/flush', Flush),

                               ('/wiki', MainWiki),
                               ('/wiki' + PAGE_RE, Wiki),
                               ('/wiki/_edit' + PAGE_RE, Edit)],
                               debug=True)
