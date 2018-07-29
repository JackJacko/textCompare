from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.txtCompareDB
Users = db["Users"]

def verify_pw(usr, pwd):
    h_pwd = Users.find({"Username":usr})[0]["Password"]

    if bcrypt.hashpw(pwd.encode('utf8'), h_pwd) == h_pwd:
        return True
    else:
        return False

def check_username(usr):
    if Users.find({"Username":usr},{"Username":1}).count() > 0:
        return True
    else:
        return False

def check_tokens(usr):
    tokenNum = Users.find({"Username":usr})[0]["Tokens"]
    return tokenNum

class Register(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data:
            retErr = {
                "Message": "An error happened.",
                "Status code": 301,
                "Error": "Input data is missing."
            }
            return jsonify(retErr)
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        # check if username is in use
        if check_username(usr):
            retErr = {
                "Message": "An error happened.",
                "Status code": 302,
                "Error": "Username is already taken."
            }
            return jsonify(retErr)
        # hash the password
        h_pwd = bcrypt.hashpw(pwd.encode('utf8'), bcrypt.gensalt())
        # store username and hashed password
        Users.insert_one({
            "Username": usr,
            "Password": h_pwd,
            "Tokens": 10
        })
        # confirm successful registration
        retJson = {
            "Status code": 200,
            "Message": "Your registration was successful."
        }
        return jsonify(retJson)

class Compare(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data or 'Text1' not in Data or 'Text2' not in Data:
            retErr = {
                "Message": "An error happened.",
                "Status code": 301,
                "Error": "Input data is missing."
            }
            return jsonify(retErr)
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        txt1 = Data['Text1']
        txt2 = Data['Text2']
        # check if username is registered
        if not check_username(usr):
            retErr = {
                "Message": "An error happened.",
                "Status code": 303,
                "Error": "Username not present in database. Please register."
            }
            return jsonify(retErr)
        # check if password is correct
        if not verify_pw(usr, pwd):
            retErr = {
                "Message": "An error happened.",
                "Status code": 304,
                "Error": "Wrong password."
            }
            return jsonify(retErr)
        # check token amount
        tkn = check_tokens(usr)
        if tkn <= 0:
            retErr = {
                "Message": "An error happened.",
                "Status code": 305,
                "Error": "Insufficient tokens. Please buy more tokens."
            }
            return jsonify(retErr)
        # compare text and calculate similarity (edit distance)
        # similarity is given between 0 and 1 where 1 is max similarity
        nlp = spacy.load('en_core_web_sm')
        text1 = nlp(txt1)
        text2 = nlp(txt2)
        ratio = text1.similarity(text2)
        # Return similarity, update tokens and report success
        Users.update_one({
            "Username": usr
        }, {
            "$set": {
                "Tokens": tkn - 1
            }
        })
        retJson = {
            "Status code": 200,
            "Message": "Similarity successfully calculated.",
            "Similarity value": ratio,
            "Tokens remaining": check_tokens(usr)
        }
        return jsonify(retJson)

class Refill(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data or 'RefillAmount' not in Data:
            retErr = {
                "Message": "An error happened.",
                "Status code": 301,
                "Error": "Input data is missing."
            }
            return jsonify(retErr)
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        rfl = Data['RefillAmount']
        # check if username is registered
        if not check_username(usr):
            retErr = {
                "Message": "An error happened.",
                "Status code": 303,
                "Error": "Username not present in database. Check spelling."
            }
            return jsonify(retErr)
        # check if password is correct
        if not verify_pw("admin", pwd):
            retErr = {
                "Message": "An error happened.",
                "Status code": 306,
                "Error": "Wrong admin password. Admin access only."
            }
            return jsonify(retErr)
        # update tokens and return success
        tkn = check_tokens(usr)
        Users.update_one({
            "Username": usr
        }, {
            "$set": {
                "Tokens": tkn + rfl
            }
        })
        retJson = {
            "Status code": 200,
            "Message": "Tokens successfully refilled.",
            "Current token amount": check_tokens(usr)
        }
        return jsonify(retJson)

api.add_resource(Register, "/signup")
api.add_resource(Compare, "/compare")
api.add_resource(Refill, "/refill")

if __name__=="__main__":
    app.run(host ='0.0.0.0', debug = True)
