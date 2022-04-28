# JWT-Secrets
## Theory 
The most common signing algorithms used in JWTs are HS256 and RS256. The first is a symmetric signing scheme using a HMAC with the SHA256 hash function. The second is an asymmetric signing scheme based on RSA.

A lot of guides on the internet recommend using HS256 as it's more straightforward. The secret key used to sign a token is the same as the key used to verify it.

However, if the signing secret key is compromised, an attacker can sign arbitrary tokens and forge sessions of other users, potentially causing total compromise of a web app. HS256 makes the secret key harder to secure than an asymmetric key-pair, as the key must be available on all servers that verify HS256 tokens (unless better infrastructure with a separate token verifying service is in place, which usually isn't the case). In contrast, with the asymmetric scheme of RS256, the signing key can be better protected while the verifying key is distributed freely.

Or even worse, developers sometimes use a default or weak HS256 secret key.

Here is a snippet of source code with one function to create a session and another function to authorise a session and check for admin permissions. But there's a strange comment about the secret key. What are you going to do?

## Code

```python
#!/usr/bin/env python3
import jwt # note this is the PyJWT module, not python-jwt


SECRET_KEY = ? # TODO: PyJWT readme key, change later
FLAG = ?


@chal.route('/jwt-secrets/authorise/<token>/')
def authorise(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except Exception as e:
        return {"error": str(e)}

    if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}


@chal.route('/jwt-secrets/create_session/<username>/')
def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': False}, SECRET_KEY, algorithm='HS256')
    return {"session": encoded}
 ```
## Solution
As we can see in the code the function that creates the session is using the jwt library, and the function receives an username, and with the jwt.encode() generates a jwt session with your username, if you are admin + the secret key following the **HS256** algorithm. 

As we know the secret key used to sign a token is the same as the key used to verify it. And if we look at the code we can see that there is a comment in the SECRET_KEY variable that says:
```python
SECRET_KEY = ? # TODO: PyJWT readme key, change later
```
If we look at the documentation of the library we can figure out that the secret key is 'secret' so the only thing we have to do here is change a little bit the code to create a session with the same username, changing the 'admin' part from false to **true**. 
## Final Code:
```python 
#!/usr/bin/env python3
#We only need the create_session function 
import jwt

SECRET_KEY = "secret"

def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': True}, SECRET_KEY, algorithm='HS256')
    return {"session": encoded}

print(create_session("kaoxx"))
```
Changing this we generate the following JWT
```javascript
session': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imthb3h4IiwiYWRtaW4iOnRydWV9.9lntclywsCx9BrESitkF7Pg6CsPo86BOG0RfH9NwJ7g'
```
And the only thing we have to do is input the JWT in the website to get the flag
```javascript
{"response":"Welcome admin, here is your flag: crypto{jwt_secret_keys_must_be_protected}"}
```


