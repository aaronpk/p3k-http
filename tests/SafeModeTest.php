<?php
namespace p3k\HTTP\Tests;

use p3k\HTTP;
use PHPUnit\Framework\TestCase;

class SafeModeTest extends TestCase {

  const DNS = [
    'a.example' => ['93.184.216.34'],
    'b.example' => ['93.184.216.35', '2606:2800:220:1::'],
    'internal.example' => ['10.0.0.5'],
  ];

  private function http(array $responses, &$transport) {
    $transport = new RecordingTransport($responses);
    $http = new HTTP('test', $transport);
    $http->set_safe_mode(true, [], function($host) { return self::DNS[$host] ?? []; });
    return $http;
  }

  public function testBlockedUrlMakesNoRequest() {
    $http = $this->http([], $transport);
    foreach(['gopher://127.0.0.1:6379/_FLUSHALL', 'file:///etc/passwd', 'http://127.0.0.1/', 'https://internal.example/'] as $url) {
      $response = $http->post($url, 'x');
      $this->assertSame('blocked_url', $response['error'], $url);
      $this->assertSame(0, $response['code']);
    }
    $this->assertSame([], $transport->requests);
  }

  public function testRequestIsPinnedToCheckedAddresses() {
    $http = $this->http(['https://b.example/' => [200, '', 'ok']], $transport);
    $response = $http->get('https://b.example/');
    $this->assertSame(200, $response['code']);
    $this->assertSame(['b.example:443:93.184.216.35', 'b.example:443:[2606:2800:220:1::]'], $transport->requests[0]['pinned']);
    $this->assertSame(0, $transport->max_redirects);
  }

  public function testRedirectToPrivateAddressIsRefused() {
    $http = $this->http([
      'https://a.example/' => [302, "Location: http://169.254.169.254/latest/meta-data/\r\n", ''],
    ], $transport);
    $response = $http->get('https://a.example/');
    $this->assertSame('blocked_url', $response['error']);
    $this->assertCount(1, $transport->requests);
  }

  public function testRedirectToOtherSchemeIsRefused() {
    $http = $this->http([
      'https://a.example/token' => [307, "Location: gopher://a.example:6379/_x\r\n", ''],
    ], $transport);
    $this->assertSame('blocked_url', $http->post('https://a.example/token', 'code=1')['error']);
    $this->assertCount(1, $transport->requests);
  }

  public function testRedirectsAreFollowedKeepingMethodAndBody() {
    $http = $this->http([
      'https://a.example/one' => [301, "Location: /two\r\n", ''],
      'https://a.example/two' => [200, "Content-Type: text/plain\r\n", 'done'],
    ], $transport);
    $response = $http->post('https://a.example/one', 'body', ['Authorization: Bearer secret']);
    $this->assertSame(200, $response['code']);
    $this->assertSame('done', $response['body']);
    $this->assertSame('https://a.example/two', $response['url']);
    $this->assertSame('POST', $transport->requests[1]['method']);
    $this->assertSame('body', $transport->requests[1]['body']);
    $this->assertContains('Authorization: Bearer secret', $transport->requests[1]['headers']);
  }

  public function testCredentialsAreDroppedWhenARedirectLeavesTheOrigin() {
    $http = $this->http([
      'https://a.example/' => [302, "Location: https://b.example/\r\n", ''],
      'https://b.example/' => [200, '', 'ok'],
    ], $transport);
    $http->get('https://a.example/', ['Authorization: Bearer secret', 'Cookie: a=b', 'Accept: text/html']);
    $this->assertSame(['Accept: text/html', 'User-Agent: test'], $transport->requests[1]['headers']);
  }

  public function testTooManyRedirects() {
    $http = $this->http([
      'https://a.example/loop' => [302, "Location: /loop\r\n", ''],
    ], $transport);
    $http->set_max_redirects(3);
    $response = $http->get('https://a.example/loop');
    $this->assertSame('too_many_redirects', $response['error']);
    $this->assertCount(4, $transport->requests);
  }

  public function testOffByDefault() {
    $transport = new RecordingTransport([]);
    $http = new HTTP('test', $transport);
    $this->assertFalse($http->safe_mode());
    $http->get('http://127.0.0.1/');
    $this->assertCount(1, $transport->requests);
    $this->assertNull($transport->requests[0]['pinned']);
    $this->assertSame(8, $transport->max_redirects);
  }
}
