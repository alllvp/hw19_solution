import calendar
import datetime, jwt

from flask import request, abort
from flask_restx import Resource, Namespace

from implemented import user_service
from constants import secret, algo

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        data = request.json
        if 'username' not in data or 'password' not in data:
            return {"error": "Неверные учётные данные"}, 401
        user = user_service.get_filtered(data['username'], user_service.get_hash(data['password']))
        if not user:
            return {"error": "Неверные учётные данные"}, 401

        data = {"username": user.username, "role": user.role}
        sec30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(sec30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        d130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(d130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        return {'access_token': access_token, 'refresh_token': refresh_token}, 201, {"location": f"/auth/{user.id}"}

    def put(self):
        data = request.json
        if 'refresh_token' not in data:
            return {"error": "Неверные учётные данные"}, 400
        try:
            token = jwt.decode(data['refresh_token'].split('Bearer ')[-1], secret, algorithms=[algo])
        except Exception as e:
            abort(401)

        data = {'username': token['username'], 'role': token['role']}
        sec30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(sec30.timetuple())
        access_token = jwt.encode(data, 's3cR$eT', algorithm=algo)

        d130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(d130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        return {'access_token': access_token, 'refresh_token': refresh_token}, 201
