<?php


namespace Klimesf\Security;

use Firebase\JWT\ExpiredException;
use Klimesf\Security\JWT\IJsonWebTokenService;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Security\Identity;
use Nette\Security\IIdentity;
use Nette\Security\IUserStorage;
use Nette\Utils\DateTime;

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
	 * @var array
	 */
	private $jwtData;

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
	 * JWTUserStorage constructor.
	 * @param string               $privateKey
	 * @param string               $algorithm
	 * @param Request              $request
	 * @param Response             $response
	 * @param IJsonWebTokenService $jsonWebTokenService
	 * @param IIdentitySerializer  $identitySerializer
	 */
	public function __construct($privateKey, $algorithm, Request $request, Response $response,
								IJsonWebTokenService $jsonWebTokenService, IIdentitySerializer $identitySerializer)
	{
		$this->privateKey = $privateKey;
		$this->algorithm = $algorithm;
		$this->request = $request;
		$this->response = $response;
		$this->jwtService = $jsonWebTokenService;
		$this->identitySerializer = $identitySerializer;
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
		if (!$this->loadJWTCookie()) {
			return false;
		}
		return $this->jwtData['is_authenticated'];
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
		if (!$this->loadJWTCookie()) {
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
		}
		$jwt = $this->jwtService->encode($this->jwtData, $this->privateKey, $this->algorithm);
		$this->response->setCookie(self::COOKIE_NAME, $jwt, $this->expirationTime);
	}

	/**
	 * Loads JWT from HTTP cookie and stores the data into the $jwtData variable.
	 * @return array|bool The JWT data as array or FALSE if there is no JWT cookie.
	 */
	private function loadJWTCookie()
	{
		$jwtCookie = $this->request->getCookie(self::COOKIE_NAME);
		if (!$jwtCookie) {
			$this->logoutReason = self::INACTIVITY | self::BROWSER_CLOSED;
			return false;
		}

		try {
			$this->jwtData = (array) $this->jwtService->decode($jwtCookie, $this->privateKey, [$this->algorithm]);

		} catch (ExpiredException $e) {
			$this->logoutReason = self::INACTIVITY;
			return false;
		}

		return $this->jwtData;
	}
}