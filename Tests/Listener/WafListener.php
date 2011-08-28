<?php

/**
 * This file is applied CC0 <http://creativecommons.org/publicdomain/zero/1.0/>
 */

namespace Societo\Util\WafBundle\Tests\Listener;

use Societo\Util\WafBundle\Listener\WafListener as Listener;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class WafListener extends \PHPUnit_Framework_TestCase
{
    public function testOnKernelRequest()
    {
        $request = new Request(array(
            'legal' => "\x2Fvalue",
            'illegal' => "\xC0\xAFvalue",
            'incomplete' => "\xE1value",
            'control' => "\t\n\r\x00\x7Fvalue",
            'might_be_xss' => '<script>alert(0);</script>',
        ));

        $event = $this->getRequestEventMock(clone $request);
        $listener = new Listener($this->getContainer());
        $listener->onKernelRequest($event);

        $this->assertEquals('/value', $event->getRequest()->query->get('legal'));
        $this->assertEquals('value', $event->getRequest()->query->get('illegal'));
        $this->assertEquals('value', $event->getRequest()->query->get('incomplete'));
        $this->assertEquals("\t\n\rvalue", $event->getRequest()->query->get('control'));

        $event = $this->getRequestEventMock(clone $request);
        $event->expects($this->once())
            ->method('setResponse');
        $listener = new Listener($this->getContainer(array(
            'societo_waf.filter_utf8_chars' => false,
            'societo_waf.filter_control_chars' => false,
            'societo_waf.deny_request_patterns' => array(
                '/<script>/',
            ),
        )));
        $listener->onKernelRequest($event);
        $this->assertEquals("\xE1value", $event->getRequest()->query->get('incomplete'));
        $this->assertEquals("\t\n\r\x00\x7Fvalue", $event->getRequest()->query->get('control'));
    }

    public function testOnKernelResponse()
    {
        $listener = new Listener($this->getContainer());

        $event = $this->getResponseEventMock(new Response(''));
        $listener->onKernelResponse($event);

        $this->assertEquals('nosniff', $event->getResponse()->headers->get('X-Content-Type-Options'));
        $this->assertFalse($event->getResponse()->headers->has('X-Frame-Options'));
        $this->assertFalse($event->getResponse()->headers->has('X-XSS-Protection'));
        $this->assertFalse($event->getResponse()->headers->has('X-Content-Security-Policy'));

        $listener = new Listener($this->getContainer(array(
            'societo_waf.disable_mime_sniffing' => false,
            'societo_waf.x_frame_options' => 'DENY',
            'societo_waf.x_xss_protection' => true,
            'societo_waf.csp' => 'allow \'self\' *.example.com',
            'societo.hsts_expire_time' => '3600',
        )));
        $event = $this->getResponseEventMock(new Response(''));
        $listener->onKernelResponse($event);

        $this->assertFalse($event->getResponse()->headers->has('X-Content-Type-Options'));
        $this->assertEquals('DENY', $event->getResponse()->headers->get('X-Frame-Options'));
        $this->assertEquals('1', $event->getResponse()->headers->get('X-XSS-Protection'));
        $this->assertEquals('allow \'self\' *.example.com', $event->getResponse()->headers->get('X-Content-Security-Policy'));
        $this->assertEquals('max-age=3600', $event->getResponse()->headers->get('Strict-Transport-Security'));
    }

    protected function getRequestEventMock($request)
    {
        $event = $this->getMock('Symfony\Component\HttpKernel\Event\GetResponseEvent', array(), array(), '', false);
        $event->expects($this->any())
            ->method('getRequest')
            ->will($this->returnValue($request));

        return $event;
    }

    protected function getResponseEventMock($response)
    {
        $event = $this->getMock('Symfony\Component\HttpKernel\Event\FilterResponseEvent', array(), array(), '', false);
        $event->expects($this->any())
            ->method('getResponse')
            ->will($this->returnValue($response));

        return $event;
    }

    protected function getContainer($parameters = array())
    {
        $parameters = array_merge(array(
            'societo_waf.filter_utf8_chars' => true,
            'societo_waf.filter_control_chars' => true,
            'societo_waf.disable_mime_sniffing' => true,
        ), $parameters);

        return new Container(new ParameterBag($parameters));
    }
}
