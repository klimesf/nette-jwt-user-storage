<?php


namespace Klimesf\Security;

use Firebase\JWT\ExpiredException;
use Klimesf\Security\JWT\IJsonWebTokenService;
use Nette\Http\Request;
use Nette\Http\Response;
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

	/** Name of the JWT access token cookie. */
	const COOKIE_NAME = 'jwt_access_token';

	/**
	 * @var Request
	 */
	private $request;

	/**
	 * @var Response
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
	 * @var boolean
	 */
	private $cookieSaved;

	/**
	 * JWTUserStorage constructor.
	 * @param string               $privateKey
	 * @param string               $algorithm
	 * @param Request              $request
	 * @param Response             $response
	 * @param IJsonWebTokenService $jsonWebTokenService
	 * @param IIdentitySerializer  $identitySerializer
	 */
	public function __construct($privateKey, $algorithm, Request $request,
								Response $response, IJsonWebTokenService $jsonWebTokenService,
								IIdentitySerializer $identitySerializer)
	{
		$this->privateKey = $privateKey;
		$this->algorithm = $algorithm;
		$this->request = $request;
		$this->response = $response;
		$this->jwtService = $jsonWebTokenService;
		$this->identitySerializer = $identitySerializer;
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
	 * @return $this
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
	 * @return void
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
	 * @return void
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
			$this->response->deleteCookie(self::COOKIE_NAME);
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
		$this->response->setCookie(self::COOKIE_NAME, $jwt, $this->expirationTime);
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

		$jwtCookie = $this->request->getCookie(self::COOKIE_NAME);
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
