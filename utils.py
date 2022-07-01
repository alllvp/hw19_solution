import jwt
from flask import request, abort

from constants import secret, algo


def auth_required(func):
    def wrapped(*args, **kwargs):
        try:
            jwt.decode(request.headers['Authorization'].split('Bearer ')[-1], secret, algorithms=[algo])
        except Exception as e:
            abort(401)
        return func(*args, **kwargs)

    return wrapped


def admin_required(func):
    def wrapped(*args, **kwargs):
        try:
            token = jwt.decode(request.headers['Authorization'].split('Bearer ')[-1], secret, algorithms=[algo])
        except Exception as e:
            abort(401)
        if token['role'] == 'admin':
            return func(*args, **kwargs)
        else:
            abort(403)

    return wrapped
