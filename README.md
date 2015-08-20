# nette-jwt-user-storage
Nette IUserStorage implementation using JWT access token instead of PHP sessions.

> Disclaimer: If you don't know what JWT is, please refer to
> [JWT draft](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32) or to  [JWT homepage](http://jwt.io/).

On user login, the application stores `jwt_access_token` cookie instead of bad old `PHPSESSID` one.
The cookie contains an encoded JWT signed by the application. The user authentication is then based
on verifying the JWT rather than the session.

> Warning: CSRF protection rules still apply!

This means you no longer need to solve PHP session implementation, scaling and testing problems.
All the things that you would normally store in the `SessionStorage` can be stored in a key-value
storage, where the JWT is a key.

This also means your application is ready to become SPA in the future. :)

No more problems with ugly PHP sessions!


Configuration
-------------

Register the extension in your `config.neon`.

```yml
extensions:
	jwtUserStorage: Klimesf\Security\DI\JWTUserStorageExtension
```

Then configure its properties.

```yml
JWTUserStorage:
	privateKey: 'secret-cat'    # this secret is used to sign the JWT
	algorithm: 'HS256'          # this is the signing algorithm
```

And that's it, you're ready to go!


Literature
----------

- [Stormpath: Where to store JWTs](https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage/)
- [Reddit: JWT vs session cookies](https://www.reddit.com/r/webdev/comments/3afcs9/jwt_vs_session_cookies_authentication/)
- [Dev Kimchi](http://devkimchi.com/1622/can-json-web-token-jwt-be-an-alternative-for-session/)