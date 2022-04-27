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
The traditional way to store sessions is with session ID cookies. After you login to a website, a session object is created for you on the backend (the server), and your browser (the client) is given a cookie which identifies that object. As you make requests to the site, your browser automatically sends the session ID cookie to the backend server, which uses that ID to find your session in its own memory and thus authorise you to perform actions.

JWTs work differently. After you login, the server sends your web browser the whole session object in a JWT, containing a payload of key-value pairs describing your username, privileges, and other info. Also included is a signature created using the server's secret key, designed to prevent you from tampering with the payload. Your web browser saves the token into local storage.

<p align="center">
  <img src="https://cryptohack.org/static/img/jwt-usage.png" alt="Sublime's custom image"/>
</p>
