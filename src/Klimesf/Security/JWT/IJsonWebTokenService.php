<?php


namespace Klimesf\Security\JWT;

use \DomainException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use \UnexpectedValueException;

/**
 * Interface meant to be implemented by a service which can encode and decode JWTs.
 * @package   Klimesf\Security\JWT
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
interface IJsonWebTokenService
{

	/**
	 * Converts and signs a PHP object or array into a JWT string.
	 *
	 * @param object|array  $payload    PHP object or array
	 * @param string        $key        The secret key.
	 *                                  If the algorithm used is asymmetric, this is the private key
	 * @param string        $alg        The signing algorithm.
	 *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 * @param array         $head       An array with header elements to attach
	 *
	 * @return string A signed JWT
	 *
	 * @uses jsonEncode
	 * @uses urlsafeB64Encode
	 */
	function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null);

	/**
	 * Decodes a JWT string into a PHP object.
	 *
	 * @param string            $jwt            The JWT
	 * @param string|array|null $key            The key, or map of keys.
	 *                                          If the algorithm used is asymmetric, this is the public key
	 * @param array             $allowed_algs   List of supported verification algorithms
	 *                                          Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 *
	 * @return object The JWT's payload as a PHP object
	 *
	 * @throws DomainException              Algorithm was not provided
	 * @throws UnexpectedValueException     Provided JWT was invalid
	 * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
	 * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
	 * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
	 * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
	 *
	 * @uses jsonDecode
	 * @uses urlsafeB64Decode
	 */
	function decode($jwt, $key, $allowed_algs = array());

}