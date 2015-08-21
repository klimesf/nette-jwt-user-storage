# nette-jwt-user-storage 

[![Join the chat at https://gitter.im/klimesf/nette-jwt-user-storage](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/klimesf/nette-jwt-user-storage?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Latest Stable Version](https://poser.pugx.org/klimesf/nette-jwt-user-storage/version)](https://packagist.org/packages/klimesf/nette-jwt-user-storage)
[![License](https://poser.pugx.org/klimesf/nette-jwt-user-storage/license)](https://packagist.org/packages/klimesf/nette-jwt-user-storage)
[![Build Status](https://travis-ci.org/klimesf/nette-jwt-user-storage.svg)](https://travis-ci.org/klimesf/nette-jwt-user-storage)

[![JWT](http://jwt.io/assets/badge-compatible.svg)](http://jwt.io/)

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


Configuration
-------------

Register the extension in your `config.neon`.

```yml
extensions:
	jwtUserStorage: Klimesf\Security\DI\JWTUserStorageExtension
```

Then configure its required properties.

```yml
JWTUserStorage:
	privateKey: 'secret-cat'    # this secret is used to sign the JWT
	algorithm: 'HS256'          # this is the signing algorithm
```

Both the JWT and the cookie in which it's stored is by default set to expire in 20 days. If you want to fiddle
with expiration time, use `expiration` option:

```yml
JWTUserStorage:
	expiration: 20 days     # sets JWT and cookie expiration time to 20 days (this is the default option)
	expiration: 20 minutes  # sets JWT and cookie expiration time to 20 minutes
	expiration: false       # sets JWT and cookie to never expire
```

By default, `jti` and `iat` (see [JWT draft](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32)) are added
to your JWTs. If you don't want to use them, set `generateJti` and `generateIat` options to false.

```yml
JWTUserStorage:
	generateJti: false          # disables jti generation for your JWT access tokens
	generateIat: false          # disables iat generation for your JWT access tokens
```

If you want to define your own `Nette\Security\IIdentity` serializer, which serializes your identity implementation
into the JWT body, you can implement `Klimesf\Security\IIdentitySerializer`

```
namespace Your\Own;

class IdentitySerializer implements \Klimesf\Security\IIdentitySerializer
{
	// ...
}
```

and register it in configuration.

```yml
JWTUserStorage:
	identitySerializer: Your\Own\IdentitySerializer
```


And that's it, you're ready to go!


Known issues
------------

- If you are developing an app with JWT User Storage and you still see `PHPSESSID` in your cookies, it's
 probably because [Tracy\Tracy](https://github.com/tracy/tracy) uses it.


Discussion threads
------------------

- Czech discussion thread on [Nette Forum](https://forum.nette.org/cs/24081-nette-jwt-user-storage-dejte-sbohem-php-session#p161518)


Literature
----------

- [Stormpath: Where to store JWTs](https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage/)
- [Reddit: JWT vs session cookies](https://www.reddit.com/r/webdev/comments/3afcs9/jwt_vs_session_cookies_authentication/)
- [Dev Kimchi](http://devkimchi.com/1622/can-json-web-token-jwt-be-an-alternative-for-session/)
- [JTI Generation](https://github.com/bshaffer/oauth2-server-php/issues/265)
