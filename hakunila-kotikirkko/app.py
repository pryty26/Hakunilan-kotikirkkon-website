print("author: yang/pryty26(back-end)\nWearTime(front-end)\nVoltex(this guy has been slacking off at working!!!)")
import os
import time
import logging
import secrets
from functools import wraps
from logging.handlers import RotatingFileHandler
import json
from sign_up_and_in_and_check import *
from flask import (
    Flask,
    request,
    render_template,
    session,
    redirect,
    url_for
)
from datetime import datetime
from activities import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from upload_file_api import *
print("import successful")


app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if '/admin/' in request.path:
        response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response


app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
'''
import requests
app.url = os.environ.get('FLASK_URL', None)
def onrender_free_keep_alive(time_sleep:int=600,our_url=app.url):
        if not our_url:
            our_url = input("please write url")
        while True:
            requests.get(our_url)
            time.sleep(time_sleep)
    '''

def generate_token(token_name:str="csrf_token"):
    if session.get(token_name) is None:
        session[token_name] = secrets.token_urlsafe(32)
    return session[token_name]
def validate_csrf(token:str,token_name="csrf_token"):
    if not token:
        return {'success':False,'message':"token missing"}
    expected = session.get(token_name)
    if not expected:
        print("token not found")
        logging.error(f"{token_name} not found")
        return {'success':False,'message':"token not found"}
    success = secrets.compare_digest(token, expected)
    return {'success':success}
@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_token(),
            "surprise_easter_egg":"eeh...surprise?",
            "api_token": generate_token('api_token')}

def token_protect(token_name="csrf_token"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == "POST":
                token = request.form.get(token_name)
                result = validate_csrf(token=token,token_name=token_name)
                if not result['success'] and result['message'] == 'token missing':
                    return "I'm a teapot(WearTime, Yang/pryty26 and voltex is the most handsome)",426
                elif not result['success']:
                    return "token is invalid or missing",403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

csrf_protect = token_protect()
api_protect = token_protect('api_token')

handler = RotatingFileHandler(
    'webpage.log',
    maxBytes=10*1024*1024,
    backupCount=3
)

logging.basicConfig(
    level=logging.INFO,
    format = '%(asctime)s - %(message)s',
    handlers=[handler]
)


limiter = Limiter(
    app = app,
    key_func = get_remote_address,
    default_limits = ['360 per minute'],
)
def write_file(filename:str,data:str):
    try:
        if not os.path.exists(filename):
            with open(filename,'w',encoding="utf-8") as f:
                f.write(data + "\n")
                return
        else:
            with open(filename, 'a', encoding="utf-8") as f:
                f.write(data + "\n")
                return
    except Exception as e:
        print(e)
        logging.error(e)
def admin_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not session.get('admin_id') or session.get('timestamp') + 3600 < time.time():
                return redirect('/')
        except (ValueError, TypeError):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/', methods=['get'])
#The home of website
@limiter.limit('80 per minute, 300 per hour')
def web_home():
    return render_template('home.html')
"""
@app.route('/look_more', methods=['GET'])
@limiter.limit('10 per minute,100 per hour')
def look_more_page():
    return render_template('look_more.html')
@app.route('/who_we_are'. methods=['GET'])
@limiter.limit('10 per minute,100 per hour')
def who_we_are_page():
    return render_template('who_we_are.html')
"""
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute,15 per hour')
def admin_login_page():
    # def verify_the_password(username:str,password:str) -> dict[str, any]:
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # check the password
        result = verify_the_password(username, password)
        success_value = result.get('success')
        if success_value is True or success_value == "True":
            session['username'] = username
            session['admin_id'] = secrets.token_hex(32)
            session['timestamp'] = time.time()
            return redirect('/')
        else:
            login_user = get_remote_address()
            logging.info(f"ip tried login:{login_user}")

            return render_template('login.html', message="Login False")

    return render_template('login.html')  # This line needs to be the last one
@app.route('/admin/del_activity', methods=['GET', 'POST'])
@admin_check
@csrf_protect
@limiter.limit('50 per minute,600 per hour')
def admin_del_activity_page():
    if request.method == 'POST':
        #def delete_activity(user_input, choice):

        user_input = request.form.get('user_input','').strip()
        choice = request.form.get('choice','').strip()
        commonplace_text(choice)
        if choice in ['deletefinished','poistayliajat','poistavanhat']:
            del_act_by_time()
        elif not user_input:
            return render_template('admin_del_activity.html',message="Please fill name/time")
        result = delete_activity(user_input, choice)
        if result['success'] == True:
            return render_template('admin_del_activity.html',
                                   message=f"Activity deleted successfully:\n{result['message']}")
    return render_template('admin_del_activity.html')


@app.route('/api/admin/add_file', methods=['GET', 'POST'])
@admin_check
@api_protect
@limiter.limit('50 per minute,600 per hour')
def api_add_file():
    #not done not done!
    if request.method == 'POST':
        return api_add_file()
    return {'success': False, 'message': "Please use POST method", 'easter_egg': 'Helo'}

@app.route('/admin/add_activity', methods=['GET', 'POST'])
@admin_check
@csrf_protect
@limiter.limit('50 per minute,600 per hour')
def admin_change_activity_page():
    if request.method == 'POST':
        name = request.form.get('activity_name','').strip()
        the_time = request.form.get('activity_time','').strip()
        author = session.get('username','Unknown')

        introduction = request.form.get('activity_introduction','').strip()
        if not name or not the_time:
            return render_template('admin_add_activity.html',
                                   message="Please fill all the fields")
        try:
            activity_time = datetime.strptime(the_time, '%d-%m-%Y %H:%M')
            fi_time = activity_time.strftime('%d-%m-%Y %H:%M')
        except ValueError:
            return render_template('admin_add_activity.html',
                                   message=
                                   "time format error Please use: DD-MM-YYYY HH:MM Format"
                                   "for example: 24-12-2024 14:30")
        #add_activity(name, fi_time, time_iso, author):
        time_iso = activity_time.isoformat()
        add_activity(name, fi_time, time_iso, author,introduction)

        return render_template('admin_add_activity.html', message=
                               "Activity added successfully")
    return render_template('admin_add_activity.html',)

