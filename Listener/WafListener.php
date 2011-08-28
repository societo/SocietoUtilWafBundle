<?php

/**
 * SocietoUtilWafBundle
 * Copyright (C) 2011 Kousuke Ebihara
 *
 * This program is under the EPL/GPL/LGPL triple license.
 * Please see the Resources/meta/LICENSE file that was distributed with this file.
 */

namespace Societo\Util\WafBundle\Listener;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

use Symfony\Component\HttpFoundation\Response;

class WafListener
{
    protected $container;

    public function __construct($container)
    {
        $this->container = $container;
    }

    public function onKernelRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $properties = array('attributes', 'request', 'query', 'server', 'cookies', 'headers');

        try {
            foreach ($properties as $property) {
                $filtered = $this->filterRequest($request->$property->all(), $property);
                $request->$property->replace($filtered);
            }
        } catch (\RuntimeException $e) {
            $event->setResponse(new Response('Your request has been blocked', 403));
        }
    }

    public function onKernelResponse(FilterResponseEvent $event)
    {
        $this->addExtraResponseHeader($event->getResponse());
    }

    /**
     * Convert encoding UTF-8 to UTF-8 for remove invalid characters
     *
     * Invalid UTF-8 character may cause security problem, so we need to truncate such characters.
     * Read "2.  UTF-8 definition" and "6.  Security Considerations" of RFC 2279 (UTF-8, a transformation format of ISO 10646)
     */
    protected function removeInvalidUtf8Characters($value)
    {
        if (function_exists('mb_convert_encoding')) {
            return mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        } elseif (function_exists('iconv')) {
            return @iconv('UTF-8', 'UTF-8//IGNORE', $value);
        }

        return $value;
    }

    /**
     * Remove all control characters except HT, LF and CR
     *
     * Control characters may cause security problem (e.g. null byte attack)
     */
    protected function removeControlCharacter($value)
    {
        return preg_replace('/[^\t\n\r[:^cntrl:]]/', '', $value);
    }

    protected function checkUnexpectedPatterns($value, $context)
    {
        if (!$this->container->hasParameter('societo_waf.deny_request_patterns')) {
            return true;
        }

        $blacklist = (array)$this->container->getParameter('societo_waf.deny_request_patterns');
        foreach ($blacklist as $pattern) {
            if (preg_match($pattern, $value)) {
                return false;
            }
        }

        return true;
    }

    protected function addExtraResponseHeader($response)
    {
        // append X-Content-Type-Options: sniff
        // http://blogs.msdn.com/b/ie/archive/2010/10/26/mime-handling-changes-in-internet-explorer.aspx
        if ($this->container->getParameter('societo_waf.disable_mime_sniffing')) {
            $response->headers->set('X-Content-Type-Options', 'nosniff');
        }

        // append X-Frame-Options: (DENY|SAMEORIGIN)
        // https://developer.mozilla.org/en/the_x-frame-options_response_header
        if ($this->container->hasParameter('societo_waf.x_frame_options')) {
            $response->headers->set('X-Frame-Options', $this->container->getParameter('societo_waf.x_frame_options'));
        }

        // append X-XSS-Protection
        if ($this->container->hasParameter('societo_waf.x_xss_protection')) {
            $response->headers->set('X-XSS-Protection', (int)(bool)$this->container->getParameter('societo_waf.x_xss_protection'));
        }

        // append X-Content-Security-Policy
        // https://developer.mozilla.org/en/Security/CSP/CSP_policy_directives
        // https://developer.mozilla.org/en/Security/CSP/Using_Content_Security_Policy
        if ($this->container->hasParameter('societo_waf.csp')) {
            $response->headers->set('X-Content-Security-Policy', $this->container->getParameter('societo_waf.csp'));
        }

        // append Strict-Transport-Security
        // https://developer.mozilla.org/en/Security/HTTP_Strict_Transport_Security
        if ($this->container->hasParameter('societo.hsts_expire_time')) {
            $response->headers->set('Strict-Transport-Security', 'max-age='.$this->container->getParameter('societo.hsts_expire_time'));
        }
    }

    protected function filterRequest($value, $context)
    {
        if (is_scalar($value)) {
            if ($this->container->getParameter('societo_waf.filter_utf8_chars')) {
                $value = $this->removeInvalidUtf8Characters($value);
            }

            if ($this->container->getParameter('societo_waf.filter_control_chars')) {
                $value = $this->removeControlCharacter($value);
            }

            if (!$this->checkUnexpectedPatterns($value, $context)) {
                throw new \RuntimeException();
            }
        } elseif (is_array($value)) {
            foreach ($value as $k => $v) {
                unset($value[$k]);
                $value[$this->filterRequest($k, $context)] = $this->filterRequest($v, $context);
            }
        }

        return $value;
    }
}
