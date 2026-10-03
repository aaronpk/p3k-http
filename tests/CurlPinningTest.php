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
    // A command string rather than an array, which proc_open only accepts as
    // of PHP 7.4. exec replaces the shell with the server, so proc_terminate
    // stops the server itself rather than just the shell.
    self::$server = proc_open(
      'exec ' . escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . self::$port . ' -t ' . escapeshellarg(__DIR__ . '/server'),
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

  // curl keeps only the last CURLOPT_RESOLVE entry for a host and port, so
  // every resolved address has to go in a single entry. Otherwise a host with
  // both IPv6 and IPv4 addresses is only tried on the last one.
  public function testTriesEveryPinnedAddress() {
    $http = new HTTP('test');
    $http->set_safe_mode(true, ['127.0.0.0/8'], function($host) {
      // Nothing listens on 127.0.0.3, so this only succeeds if curl can fall back to 127.0.0.1
      return $host === 'pinned.example' ? ['127.0.0.1', '127.0.0.3'] : [];
    });
    $response = $http->get('http://pinned.example:' . self::$port . '/');
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
