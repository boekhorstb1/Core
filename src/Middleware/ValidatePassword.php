<?php
declare(strict_types=1);

namespace Horde\Core\Middleware;


use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

use \Passwd_Factory_Driver as Factorydriver;
use \Horde\Core\Config\State as Configuration;
use \Horde_Registry;
use \Horde_Auth;
use \Horde_Auth_Exception;
use \Exception; // wofür wird das gebraucht und wo wird die Klasse herhgeholt? php exception class?


/**
 * ValidatePassword middleware
 * Returns 200 response if password is valid and correct
 * 
 * Validates Password 
 * 
 * @author    Rafael te Boekhorst <boekhorst@b1-systems.de>
 * @category  Horde
 * @copyright 2013-2021 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Core
 */
class ValidatePassword implements MiddlewareInterface
{

    private ResponseFactoryInterface $responseFactory;
    protected StreamFactoryInterface $streamFactory;
    private Factorydriver $backendchecker;
    public Configuration $config;
    private Horde_Registry $registry;

    public function __construct(   
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory,
        Factorydriver $backendchecker,
        Configuration $config,
        Horde_Registry $registry
        )
    {
        $this->responseFactory = $responseFactory;
        $this->streamFactory = $streamFactory;
        $this->backendchecker = $backendchecker;
        $this->registry = $registry;
        $this->config = $config;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {

        // getting request infos
        $post = $request->getParsedBody();
        $user = $post->username;
        $newpassword = $post->password;

        //testing
        // $newpassword = "testTest123!";
        // $user = "administrator";

        // loading user credentials
        $userid = $this->registry->getAuth();
        $credentials = $this->registry->getAuthCredential();
        $currentpassword = (string) $credentials['password'];

        // loading backendinfos and configuration
        $conf = $this->config->toArray();
        $backend = $this->backendchecker->__get('backends');
        $backend = $backend['hordeauth'];
               
        // if status is not set to 200 by checks bellow, there is a problem
        $status = 404;
        $reason = 'Please contact the administrator';
        $success = false;


        // check if the username is the correct username... users can only change their own passwords right?
        if ($userid !== $user){
            $reason = "You can't change password for user ".$user.". Please enter your own correct username.";
            $status = (int) 403;
        }
        
        
        // Check for users that cannot change their passwords.
        if ($status == 404) {
            if (in_array($userid, $conf['user']['refused'])) {
                $this->reason = "You do dont have permission to change password as user ".$user."";
                $this->status = (int) 403;
            }
        }   

        if ($status == 404) {
            // Check for password policies and apply them
            try {
                Horde_Auth::checkPasswordPolicy($newpassword, isset($backend['policy']) ? $backend['policy'] : array());
                $status = 200;
                $reason = '';
                $success = true;
            } catch (Horde_Auth_Exception $e) {
                $status = 400;
                $reason = $e->getMessage(); 
                $success = false;
            }
        }

        if ($status == 200) {
            // Do some simple strength tests, if enabled in the config file.
            if (!empty($conf['password']['strengthtests'])) {
                try {
                    Horde_Auth::checkPasswordSimilarity($newpassword, array($userid, $currentpassword));
                    $status = 200;
                    $reason = '';
                    $success = true;
                } catch (Horde_Auth_Exception $e) {
                    $status = 404;
                    $reason = $e->getMessage(); 
                    $success = false;
                }
            }

        }

        if ($status === 200) {
            return $handler->handle($request);
        }
        
        $jsonData = ['success' => $success, 'message' => 'ValidatePassword Middleware: '.$reason];
        $jsonString = json_encode($jsonData);

        $body = $this->streamFactory->createStream($jsonString);
        $response = $this->responseFactory->createResponse($status, $reason)->withBody($body)
        ->withHeader('Content-Type', 'application/json')
        ->withStatus($status, $reason);

        return $response;
    }


}

