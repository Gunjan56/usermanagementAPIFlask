from functools import wraps
from models.model import User
from flask_jwt_extended import get_jwt_identity
from flask import abort
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            if user.role not in roles:
                abort(403, 'Insufficient permissions')
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper