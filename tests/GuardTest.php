<?php
namespace p3k\HTTP\Tests;

use p3k\HTTP\Guard;
use PHPUnit\Framework\TestCase;

class GuardTest extends TestCase {

  private static function guard(array $dns = [], array $allow = []) {
    return new Guard($allow, function($host) use($dns) { return $dns[$host] ?? []; });
  }

  public static function publicAddresses() {
    return [['8.8.8.8'], ['93.184.216.34'], ['100.128.0.1'], ['198.20.0.1'], ['223.255.255.255'], ['2606:4700::1'], ['2001:4860:4860::8888'], ['64:ff9b::808:808'], ['2002:808:808::']];
  }

  public static function nonPublicAddresses() {
    return [
      ['127.0.0.1'], ['127.8.9.10'], ['10.11.11.80'], ['172.16.0.1'], ['192.168.1.1'], ['169.254.169.254'],
      ['100.64.0.1'], ['0.0.0.0'], ['::'], ['::1'], ['fe80::1'], ['fc00::1'], ['fd12:3456::1'],
      ['::ffff:127.0.0.1'], ['::ffff:10.0.0.1'], ['64:ff9b::7f00:1'], ['64:ff9b::a00:1'], ['2002:7f00:1::1'], ['2002:a9fe:a9fe::'],
      ['192.0.0.8'], ['192.0.2.1'], ['198.18.0.1'], ['198.19.255.255'], ['198.51.100.7'], ['203.0.113.5'], ['224.0.0.1'],
      ['239.255.255.250'], ['255.255.255.255'], ['100.127.255.255'], ['::ffff:8.8.8.8'], ['64:ff9b:1::1'], ['100::1'],
      ['2001::1'], ['2001:db8::1'], ['3fff::1'], ['fec0::1'], ['ff02::1'], ['not an address'], [''],
    ];
  }

  /** @dataProvider publicAddresses */
  #[\PHPUnit\Framework\Attributes\DataProvider('publicAddresses')]
  public function testPublicAddresses($address) {
    $this->assertTrue(Guard::is_public($address));
  }

  /** @dataProvider nonPublicAddresses */
  #[\PHPUnit\Framework\Attributes\DataProvider('nonPublicAddresses')]
  public function testNonPublicAddresses($address) {
    $this->assertFalse(Guard::is_public($address));
  }

  public static function blockedUrls() {
    return [
      ['gopher://127.0.0.1:6379/_SET%20x%201'], ['dict://127.0.0.1:6379/info'], ['file:///etc/passwd'],
      ['ftp://example.com/'], ['ldap://example.com/'], ['javascript:alert(1)'], ['/relative'], ['https://'],
      ['http://127.0.0.1/'], ['http://localhost.example/'], ['http://[::1]/'], ['http://[::ffff:127.0.0.1]/'],
      ['http://2130706433/'], ['http://0x7f000001/'], ['http://0177.0.0.1/'], ['http://127.1/'], ['http://0/'],
      ['http://169.254.169.254/latest/meta-data/'], ['http://mixed.example/'],
    ];
  }

  /** @dataProvider blockedUrls */
  #[\PHPUnit\Framework\Attributes\DataProvider('blockedUrls')]
  public function testBlockedUrls($url) {
    $result = self::guard(['localhost.example' => ['127.0.0.1'], 'mixed.example' => ['93.184.216.34', '10.0.0.1']])->check($url);
    $this->assertSame('blocked_url', $result['error'] ?? null, $url);
  }

  public function testPublicHostIsAllowedWithItsAddresses() {
    $result = self::guard(['example.com' => ['93.184.216.34', '2606:2800:220:1::']])->check('https://Example.com/path');
    $this->assertSame(['host' => 'example.com', 'port' => 443, 'addresses' => ['93.184.216.34', '2606:2800:220:1::']], $result);
  }

  public function testExplicitPort() {
    $result = self::guard(['example.com' => ['93.184.216.34']])->check('http://example.com:8080/');
    $this->assertSame(8080, $result['port']);
  }

  public function testUnresolvableHost() {
    $this->assertSame('dns_error', self::guard()->check('https://nowhere.example/')['error']);
  }

  public function testAllowedHost() {
    $guard = self::guard(['dev.example' => ['10.11.11.80']], ['dev.example']);
    $this->assertSame(['10.11.11.80'], $guard->check('https://dev.example/')['addresses']);
    $this->assertArrayHasKey('error', $guard->check('https://other.example/'));
  }

  public function testAllowedRange() {
    $guard = self::guard(['dev.example' => ['10.11.11.80'], 'db.example' => ['10.11.12.5']], ['10.11.11.0/24']);
    $this->assertArrayNotHasKey('error', $guard->check('https://dev.example/'));
    $this->assertArrayHasKey('error', $guard->check('https://db.example/'));
  }

  public function testAllowedSingleAddress() {
    $guard = self::guard([], ['127.0.0.1', '::1']);
    $this->assertArrayNotHasKey('error', $guard->check('http://127.0.0.1:8000/'));
    $this->assertArrayNotHasKey('error', $guard->check('http://[::1]:8000/'));
    $this->assertArrayHasKey('error', $guard->check('http://127.0.0.2/'));
  }

  public function testInCidr() {
    $this->assertTrue(Guard::in_cidr('10.11.11.80', '10.11.11.0/24'));
    $this->assertFalse(Guard::in_cidr('10.11.12.80', '10.11.11.0/24'));
    $this->assertTrue(Guard::in_cidr('10.11.11.80', '10.8.0.0/13'));
    $this->assertTrue(Guard::in_cidr('fd00::1', 'fc00::/7'));
    $this->assertFalse(Guard::in_cidr('10.0.0.1', 'fc00::/7'));
  }
}
