<?php
namespace p3k\HTTP\Tests;

use p3k\HTTP;
use p3k\HTTP\Curl;
use PHPUnit\Framework\TestCase;

// Real requests through curl to PHP's built-in server on 127.0.0.1.
class CurlPinningTest extends TestCase {

  private static $server;
  private static $port;

  public static function setUpBeforeClass(): void {
    self::$port = 20000 + random_int(0, 9999);
    self::$server = proc_open(
      [PHP_BINARY, '-S', '127.0.0.1:' . self::$port, '-t', __DIR__ . '/server'],
      [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
      $pipes
    );
    for($i = 0; $i < 50; $i++) {
      $socket = @fsockopen('127.0.0.1', self::$port);
      if($socket) { fclose($socket); return; }
      usleep(100000);
    }
    self::fail('The test server did not start');
  }

  public static function tearDownAfterClass(): void {
    proc_terminate(self::$server);
  }

  private function http() {
    $http = new HTTP('test');
    // "pinned.example" exists only in this resolver; curl can reach it only
    // through the pinned address.
    $http->set_safe_mode(true, ['127.0.0.1'], function($host) { return $host === 'pinned.example' ? ['127.0.0.1'] : []; });
    return $http;
  }

  public function testConnectsToThePinnedAddress() {
    $response = $this->http()->get('http://pinned.example:' . self::$port . '/');
    $this->assertSame(200, $response['code']);
    $this->assertSame('host=pinned.example:' . self::$port, $response['body']);
  }

  public function testRedirectsAreCheckedHopByHop() {
    $port = self::$port;
    $response = $this->http()->get("http://pinned.example:$port/?to=" . rawurlencode("http://127.0.0.1:$port/"));
    $this->assertSame(200, $response['code']);
    $this->assertSame("http://127.0.0.1:$port/", $response['url']);

    $response = $this->http()->get("http://pinned.example:$port/?to=" . rawurlencode("http://127.0.0.2:$port/"));
    $this->assertSame('blocked_url', $response['error']);
  }

  public function testPinnedCurlRefusesOtherProtocols() {
    $curl = new Curl();
    $curl->pin_addresses([]);
    $response = $curl->get('dict://127.0.0.1:' . self::$port . '/info');
    $this->assertSame(0, $response['code']);
    $this->assertNotSame('', $response['error_description']);
  }
}
