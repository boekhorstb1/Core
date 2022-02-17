<?php

declare(strict_types=1);

namespace Horde\Core\Middleware;

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Horde_Registry;
use Horde_Application;
use Horde_Controller;
use Horde_Routes_Mapper as Router;
use Horde_String;
use Horde\Core\Config\State;
use Horde;
use Horde_Url;
use Horde\Core\UserPassport;
use Psr\Http\Message\ResponseFactoryInterface;

/**
 * RedirectToLogin middleware
 *
 * Purpose: Redirect to login if not authenticated
 *
 * Reads attribute:
 * - HORDE_AUTHENTICATED_USER the uid, if authenticated
 *
 */
class RedirectToLogin implements MiddlewareInterface
{
    private State $conf;
    private Horde_Registry $registry;
    private ResponseFactoryInterface $responseFactory;
    public function __construct(Horde_Registry $registry, ResponseFactoryInterface $responseFactory, State $conf)
    {
        $this->registry = $registry;
        $this->responseFactory = $responseFactory;
        $this->conf = $conf;
    }
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($request->getAttribute('HORDE_AUTHENTICATED_USER')) {
            return $handler->handle($request);
        }

        // set baseurl: check if alternative login is set (currently this part is working)
        $configArray = $this->conf->toArray();
        $alternateLogin = $configArray['auth']['alternate_login'];
        if(!empty($alternateLogin)){
            $baseurl = $alternateLogin;
            $url = (string)$request->getUri();
            $redirect = (string)Horde::Url($baseurl, true)->add('url', $url);
        }
        // set baseurl: if no alternative login, only Horde (NOT WOKRING: I have not found any solution yet...... I do not know why passwd relink is working)
        else{
            $url = (string) $request->getUri();
            $baseurl = $this->registry->getServiceLink('login');
            $redirect = (string)$this->registry->getServiceLink('logintasks', 'passwd', true);
            $redirect = (string)Horde::Url($baseurl, true)->add('url', $url);
            $redirect = Horde::signUrl($redirect);
        };
        
        return $this->responseFactory->createResponse(302)->withHeader('Location', $redirect);
    }
}
