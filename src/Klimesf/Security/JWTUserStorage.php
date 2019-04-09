<?php


namespace Klimesf\Security;

use Firebase\JWT\ExpiredException;
use Klimesf\Security\JWT\IJsonWebTokenService;
use Nette\Http\IRequest;
use Nette\Http\IResponse;
use Nette\Security\IIdentity;
use Nette\Security\IUserStorage;
use Nette\Utils\DateTime;
use Nette\Utils\Random;

/**
 * @package   Klimesf\Security
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
class JWTUserStorage implements IUserStorage
{

	/**
	 * Name of the JWT access token cookie.
	 * @deprecated The constant is deprecated in favour of instance property $cookieName
	 */
	const COOKIE_NAME = 'jwt_access_token';

	/**
	 * @var IRequest
	 */
	private $request;

	/**
	 * @var IResponse
	 */
	private $response;

	/**
	 * @var IJsonWebTokenService
	 */
	private $jwtService;

	/**
	 * @var string
	 */
	private $privateKey;

	/**
	 * @var string
	 */
	private $algorithm;

	/**
	 * @var boolean
	 */
	private $generateJti = true;

	/**
	 * @var boolean
	 */
	private $generateIat = true;

	/**
	 * @var array
	 */
	private $jwtData = array();

	/**
	 * @var string
	 */
	private $expirationTime;

	/**
	 * @var int
	 */
	private $logoutReason;

	/**
	 * @var IIdentitySerializer
	 */
	private $identitySerializer;

	/**
	 * @var string
	 */
	private $cookiePath;

	/**
	 * @var string
	 */
	private $cookieDomain;

	/**
	 * @var bool
	 */
	private $cookieSecure;

	/**
	 * @var bool
	 */
	private $cookieHttpOnly;

	/**
	 * @var string
	 */
	private $cookieName;

	/**
	 * @var boolean
	 */
	private $cookieSaved;

	/**
	 * JWTUserStorage constructor.
	 * @param string               $privateKey
	 * @param string               $algorithm
	 * @param IRequest             $request
	 * @param IResponse            $response
	 * @param IJsonWebTokenService $jsonWebTokenService
	 * @param IIdentitySerializer  $identitySerializer
	 * @param string               $cookiePath
	 * @param string               $cookieDomain
	 * @param bool                 $cookieSecure
	 * @param bool                 $cookieHttpOnly
	 * @param string               $cookieName
	 */
	public function __construct(
		$privateKey,
		$algorithm,
		IRequest $request,
		IResponse $response,
		IJsonWebTokenService $jsonWebTokenService,
		IIdentitySerializer $identitySerializer,
		$cookiePath = null,
		$cookieDomain = null,
		$cookieSecure = null,
		$cookieHttpOnly = null,
		$cookieName = null
	) {
		$this->privateKey = $privateKey;
		$this->algorithm = $algorithm;
		$this->request = $request;
		$this->response = $response;
		$this->jwtService = $jsonWebTokenService;
		$this->identitySerializer = $identitySerializer;
		$this->cookiePath = $cookiePath;
		$this->cookieDomain = $cookieDomain;
		$this->cookieSecure = $cookieSecure;
		$this->cookieHttpOnly = $cookieHttpOnly;
		$this->cookieName = $cookieName ?: 'jwt_access_token';
	}

	/**
	 * @param boolean $generateJti
	 */
	public function setGenerateJti($generateJti)
	{
		$this->generateJti = $generateJti;
	}

	/**
	 * @param boolean $generateIat
	 */
	public function setGenerateIat($generateIat)
	{
		$this->generateIat = $generateIat;
	}

	/**
	 * Sets the authenticated status of this user.
	 * @param  bool
	 * @return static
	 */
	function setAuthenticated($state)
	{
		$this->jwtData['is_authenticated'] = $state;
		if (!$state) {
			$this->logoutReason = self::MANUAL;
		}
		$this->saveJWTCookie();
		return $this;
	}

	/**
	 * Is this user authenticated?
	 * @return bool
	 */
	function isAuthenticated()
	{
		$this->loadJWTCookie();
		return array_key_exists('is_authenticated', $this->jwtData) ? $this->jwtData['is_authenticated'] : false;
	}

	/**
	 * Sets the user identity.
	 *
	 * @param IIdentity|null $identity
	 * @return static
	 */
	function setIdentity(IIdentity $identity = null)
	{
		if (!$identity) {
			$this->jwtData = ['is_authenticated' => false];
			return;
		}
		$this->jwtData = array_merge(
			$this->jwtData,
			$this->identitySerializer->serialize($identity)
		);
		$this->saveJWTCookie();
		return $this;
	}

	/**
	 * Returns current user identity, if any.
	 * @return IIdentity|NULL
	 */
	function getIdentity()
	{
		$this->loadJWTCookie();
		if (empty($this->jwtData)) {
			return null;
		}
		return $this->identitySerializer->deserialize($this->jwtData);
	}

	/**
	 * Enables log out from the persistent storage after inactivity.
	 * @param  string|int|\DateTime $time  number of seconds or timestamp
	 * @param int                   $flags Log out when the browser is closed | Clear the identity from persistent storage?
	 * @return static
	 */
	function setExpiration($time, $flags = 0)
	{
		$this->expirationTime = $flags & self::BROWSER_CLOSED ? 0 : $time;
		if ($time) {
			$time = DateTime::from($time)->format('U');
			$this->jwtData['exp'] = $time;
		} else {
			unset($this->jwtData['exp']);
		}
		$this->saveJWTCookie();
		return $this;
	}

	/**
	 * Why was user logged out?
	 * @return int
	 */
	function getLogoutReason()
	{
		return $this->logoutReason;
	}

	/**
	 * Saves the JWT Access Token into HTTP cookie.
	 */
	private function saveJWTCookie()
	{
		if (empty($this->jwtData)) {
			$this->response->deleteCookie($this->cookieName, $this->cookiePath, $this->cookieDomain, $this->cookieSecure);
			return;
		}

		if ($this->generateIat) {
			$this->jwtData['iat'] = DateTime::from('NOW')->format('U');
		}

		// Unset JTI if there was any
		unset($this->jwtData['jti']);
		if ($this->generateJti) {
			// Generate new JTI
			$this->jwtData['jti'] = hash('sha256', serialize($this->jwtData) . Random::generate(10));
		}
		// Encode the JWT and set the cookie
		$jwt = $this->jwtService->encode($this->jwtData, $this->privateKey, $this->algorithm);
		$this->response->setCookie($this->cookieName, $jwt, $this->expirationTime, $this->cookiePath, $this->cookieDomain, $this->cookieSecure, $this->cookieHttpOnly);
		$this->cookieSaved = true; // Set cookie saved flag to true, so loadJWTCookie() doesn't rewrite our data
	}

	/**
	 * Loads JWT from HTTP cookie and stores the data into the $jwtData variable.
	 */
	private function loadJWTCookie()
	{
		if ($this->cookieSaved) {
			return;
		}

		$jwtCookie = $this->request->getCookie($this->cookieName);
		if (!$jwtCookie) {
			$this->logoutReason = self::INACTIVITY | self::BROWSER_CLOSED;
			return;
		}

		try {
			$this->jwtData = (array) $this->jwtService->decode($jwtCookie, $this->privateKey, [$this->algorithm]);
		} catch (ExpiredException $e) {
			$this->logoutReason = self::INACTIVITY;
		}
	}
}
