<?php
namespace p3k\HTTP\Tests;

use p3k\HTTP\Pinnable;
use p3k\HTTP\Transport;

// Answers from a table of canned responses and records every request it
// was asked to make, and what it was pinned to at the time.
class RecordingTransport implements Transport, Pinnable {

  public $requests = [];
  public $max_redirects = null;
  private $pinned = null;
  private $responses;

  /** @param array $responses url => [code, headers string, body] */
  public function __construct(array $responses) {
    $this->responses = $responses;
  }

  public function pin_addresses($resolve) { $this->pinned = $resolve; }
  public function set_timeout($timeout) {}
  public function set_max_redirects($max) { $this->max_redirects = $max; }

  public function get($url, $headers=[]) { return $this->answer('GET', $url, false, $headers); }
  public function post($url, $body, $headers=[]) { return $this->answer('POST', $url, $body, $headers); }
  public function put($url, $body, $headers=[]) { return $this->answer('PUT', $url, $body, $headers); }
  public function head($url, $headers=[]) { return $this->answer('HEAD', $url, false, $headers); }

  private function answer($method, $url, $body, $headers) {
    $this->requests[] = ['method' => $method, 'url' => $url, 'body' => $body, 'headers' => $headers, 'pinned' => $this->pinned];
    list($code, $header, $responseBody) = $this->responses[$url] ?? [404, '', 'not found'];
    return [
      'code' => $code,
      'header' => "HTTP/1.1 $code X\r\n" . $header,
      'body' => $responseBody,
      'error' => '',
      'error_description' => '',
      'url' => $url,
      'debug' => '',
    ];
  }
}
