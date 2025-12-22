from datetime import *
from functools import wraps
from flask import session, redirect
import time






def admin_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_id') or session.get('timestamp') + 3600 < time.time():
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function
