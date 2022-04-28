# JWT-none-alg-vulnerability
Cryptohack walk-through about the no way Jose at Crypto on the Web section of Cryptohack and thoughts about the none algorithm vulnerability in JWT
## JWT Web Token
**JSON Web Token (JWT)** is a proposed Internet standard for creating data with optional signature and optional encryption whose payloads holds JSON that asserts some number of claims. The tokens are signed either using a private secret or a public/private key.
## Structure
### Header

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
Identifies which algorithm is used to generate the signature. For example in **that** code *"HS256"* indicates that the token is signed using HMAC-SHA256. 
### Payload
```json
{
  "loggedInAs": "admin",
  "iat": 1422779638
}
```
This part contains a set of claims.The JWT specification defines seven Registered Claim names which are the **standard fields** commonly included in tokens. So custom claims are usually also included, depending on the purpose of the token. Usually contains the user logged in like in this code example **loggedInAs**.
### Signature
```
HMAC_SHA256(
  secret,
  base64urlEncoding(header) + '.' +
  base64urlEncoding(payload)
)
```
Securely validates the token. The signature is calculated by encoding the header and the payload using **Base64url** and concatenating the two together with a period separator. After that the string is run through the cryptographic algorithm specified in the header, in this case HMAC-SHA256.
## JWT Sessions
The traditional way to store sessions is with session ID cookies. After you login to a website, a session object is created for you on the back-end (the server), and your browser (the client) is given a cookie which identifies that object. As you make requests to the site, your browser automatically sends the session ID cookie to the back-end server, which uses that ID to find your session in its own memory and thus authorize you to perform actions.

JWTs work differently. After you login, the server sends your web browser the whole session object in a JWT, containing a payload of key-value pairs describing your username, privileges, and other info. Also included is a signature created using the server's secret key, designed to prevent you from tampering with the payload. Your web browser saves the token into local storage.

<p align="center">
  <img src="https://cryptohack.org/static/img/jwt-usage.png" alt="Sublime's custom image"/>
</p>

On subsequent requests, your browser sends the token to the back-end server. The server verifies the signature first, and then reads the token payload to authorize you.

The main advantage of JWTs over session ID cookies is that they are easy to scale. Organizations need a way to share sessions across multiple back-end servers. When a client switches from using one server or resource to another, that client's session should still work. Furthermore, for large orgs there could be millions of sessions. Since JWTs live on the client, they solve these problems: any back-end server can authorize a user just by checking the signature on the token and reading the data inside.

## No Way Jose
So the first part of a JWT is the JOSE header, and when you decode it, looks like this
```javascript
{"typ":"JWT","alg":"HS256"} 
```
This tells the server it's a JWT and which algorithm to use to verify it. Can you see the issue here? The server has to process this untrusted input before it is actually able to verify the integrity of the token! In ideal cryptographic protocols, you verify messages you receive before performing any further operations on them, otherwise in Moxie Marlinspike's words, "it will somehow inevitably lead to doom".

The "none" algorithm in JWTs is a case in point. The link below takes you to a page where you can interact with a broken session API, which emulates a vulnerability that existed in a lot of JWT libraries.
### Source code of the website:
[No Way Jose](http://web.cryptohack.org/no-way-jose/)
```python
import base64
import json
import jwt # note this is the PyJWT module, not python-jwt


SECRET_KEY = ?
FLAG = ?


@chal.route('/no-way-jose/authorise/<token>/')
def authorise(token):
    token_b64 = token.replace('-', '+').replace('_', '/') # JWTs use base64url encoding
    try:
        header = json.loads(base64.b64decode(token_b64.split('.')[0] + "==="))
    except Exception as e:
        return {"error": str(e)}

    if "alg" in header:
        algorithm = header["alg"]
    else:
        return {"error": "There is no algorithm key in the header"}

    if algorithm == "HS256":
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except Exception as e:
            return {"error": str(e)}
    elif algorithm == "none":
        try:
            decoded = jwt.decode(token, algorithms=["none"], options={"verify_signature": False})
        except Exception as e:
            return {"error": str(e)}
    else:
        return {"error": "Cannot decode token"}

    if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}


@chal.route('/no-way-jose/create_session/<username>/')
def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': False}, SECRET_KEY, algorithm='HS256')
    return {"session": encoded}
```
## Bypassing authorization and getting the flag.

As we see in the code when you create a session with an username lets make this with **Kaoxx** the output of the script is the JWT, in my case is:
```json
{"session":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Ikthb3h4IiwiYWRtaW4iOmZhbHNlfQ.HpS8OHa7yfF0YRKcUP3CkBPUA89lWXaKgFsZvziysWs"}
```
As we know the first part of the JWT is the header which includes the algorithm is this case is HS256 as we can see in the code and decoding **eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9** in base64 we can check it:
```json
{"typ":"JWT","alg":"HS256"}
```
The second part of the JWT is the payload and as we can see in the code it is made by the username that you input and the admin parameter set in False. We can check it decoding **eyJ1c2VybmFtZSI6Ikthb3h4IiwiYWRtaW4iOmZhbHNlfQ**
```json
{"username":"Kaoxx","admin":false}
```
So the thing here is that if we modify the header changing the algorithm part from HS256 to none and the payload from admin:false to true as we know the server has to process the untrusted input *before* it is actually able to verify the integrity of the token.
```json
{"typ":"JWT","alg":"none"} in Base64 eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=
{"username":"admin","admin":true} in Base64 eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9

```
```python
#And if we concatenate the header + payload + signature we get:
# eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9.
# HpS8OHa7yfF0YRKcUP3CkBPUA89lWXaKgFsZvziysWs
```
We get the final JWT with the changes and now if we put it in the input of the authorize(token) we can bypass the authorization.

```json
{"response":"Welcome admin, here is your flag: crypto{The_Cryptographic_Doom_Principle}"}
```
