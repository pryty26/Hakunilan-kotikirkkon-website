import os
import time
import logging
import secrets
from functools import wraps
from logging.handlers import RotatingFileHandler
import json
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for
)
from datetime import datetime
from activities import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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


@app.route('/')
#The home of website
@limiter.limit('80 per minute, 300 per hour')
def web_home():
    return render_template('home.html')

@app.route('/look_more', methods=['GET'])
@limiter.limit('10 per minute,100 per hour')
def look_more():
    return render_template('look_more.html')

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute,15 per hour')
def admin_login():
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
@limiter.limit('50 per minute,600 per hour')
def admin_del_activity():
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


@app.route('/admin/add_activity', methods=['GET', 'POST'])
@admin_check
@limiter.limit('50 per minute,600 per hour')
def admin_change_activity():
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

