A series of writeups and notes for a few challenges from PicoCTF 2023.

# Java Code Analysis!?!

- We log in with the credentials provided.
- We see several PDFs 
- We can view a normal pdf from the url `/base/books/pdf/3`. The flag is two books over, so we can infer the url of the flag is `/base/books/pdf/5`.
- Looking at the source code (SecretGenerator.java), we see that the function for creating a random string for JWT tokens is not very secure:
```js
    private String generateRandomString(int len) {
        // not so random
        return "1234";
    }
```
- We paste the token into https://jwt.io/ to generate token where the secret is `1234`. The details of the new token should look like this:
```json
{
  "role": "Admin",
  "iss": "bookshelf",
  "exp": 1679613500,
  "iat": 1679008700,
  "userId": 2,
  "email": "admin"
}
```
- We replace our token with this newly generated one, which gives us access to the flag.

Additional reading
- https://blog.pentesteracademy.com/hacking-jwt-tokens-bruteforcing-weak-signing-key-jwt-cracker-5d49d34c44

# Special
- Appears to autocorrect to a word and capitalize
- Need to escape somehow
- Inputting nothing gives output that shows it's a python script:
```
Special$ 
Traceback (most recent call last):
  File "/usr/local/Special.py", line 19, in <module>
    elif cmd[0] == '/':
IndexError: string index out of range
```
- Inputting `""""python3""""` escapes into a python shell
- Then, we can use this code to escape to regular bash:
```py
import os
os.system("/bin/sh"))
```
