<?php
namespace p3k\HTTP;

class Curl implements Transport {

  protected $_timeout = 4;
  protected $_max_redirects = 8;
  static protected $_http_version = null;
  private $_last_seen_url = null;
  private $_last_seen_code = null;
  private $_current_headers = [];
  private $_current_redirects = [];
  private $_debug_header = '';

  public function set_max_redirects($max) {
    $this->_max_redirects = $max;
  }

  public function set_timeout($timeout) {
    $this->_timeout = $timeout;
  }

  public function get($url, $headers=[]) {
    $ch = curl_init($url);
    $this->_set_curlopts($ch, $url);
    if($headers)
      curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    return [
      'code' => curl_getinfo($ch, CURLINFO_HTTP_CODE),
      'header' => implode("\r\n", array_map(function ($a) { return $a[0] . ': ' . $a[1]; }, $this->_current_headers)),
      'body' => $response,
      'redirects' => $this->_current_redirects,
      'error' => self::error_string_from_code(curl_errno($ch)),
      'error_description' => curl_error($ch),
      'url' => $this->_last_seen_url,
      'debug' => $this->_debug_header . "\r\n" . $response
    ];
  }

  public function post($url, $body, $headers=[]) {
    $ch = curl_init($url);
    $this->_set_curlopts($ch, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    if($headers)
      curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    return [
      'code' => curl_getinfo($ch, CURLINFO_HTTP_CODE),
      'header' => implode("\r\n", array_map(function ($a) { return $a[0] . ': ' . $a[1]; }, $this->_current_headers)),
      'body' => $response,
      'redirects' => $this->_current_redirects,
      'error' => self::error_string_from_code(curl_errno($ch)),
      'error_description' => curl_error($ch),
      'url' => $this->_last_seen_url,
      'debug' => $this->_debug_header . "\r\n" . $response
    ];
  }

  public function head($url, $headers=[]) {
    $ch = curl_init($url);
    $this->_set_curlopts($ch, $url);
    if($headers)
      curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    $response = curl_exec($ch);
    return [
      'code' => curl_getinfo($ch, CURLINFO_HTTP_CODE),
      'header' => implode("\r\n", array_map(function ($a) { return $a[0] . ': ' . $a[1]; }, $this->_current_headers)),
      'redirects' => $this->_current_redirects,
      'error' => self::error_string_from_code(curl_errno($ch)),
      'error_description' => curl_error($ch),
      'url' => $this->_last_seen_url,
      'debug' => $this->_debug_header . "\r\n" . $response
    ];
  }

  private function _set_curlopts($ch, $url) {
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $this->_max_redirects > 0);
    curl_setopt($ch, CURLOPT_MAXREDIRS, $this->_max_redirects);
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, round($this->_timeout * 1000));
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 2000);
    curl_setopt($ch, CURLOPT_HTTP_VERSION, $this->_http_version());
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, [$this, '_header_function']);
  }

  private function _http_version() {
    if (static::$_http_version !== null)
      return static::$_http_version;
    if (defined('CURL_HTTP_VERSION_2')) { // PHP 7.0.7
      static::$_http_version = CURL_HTTP_VERSION_2;
    } else if (defined('CURL_HTTP_VERSION_2_0')) { // Recommended in online articles
      static::$_http_version = CURL_HTTP_VERSION_2_0;
    } else { // Linked curl might be newer than PHP, send (current) INT value anyway.
      static::$_http_version = 3;
    }
    return static::$_http_version;
  }

  private function _header_function($curl, $header) {
    $this->_debug_header .= $header;
    $current_url = curl_getinfo($curl, CURLINFO_EFFECTIVE_URL);
    if ($current_url !== $this->_last_seen_url) {
        if ($this->_last_seen_url !== null) {
            $this->_current_redirects[] = [$this->_last_seen_code, $this->_last_seen_url];
        }
        $this->_current_headers = [];
        $this->_last_seen_url = $current_url;
        $this->_last_seen_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    }
    $length = strlen($header);
    $header = explode(':', $header, 2);
    if (count($header) !== 2) {
      return $length;
    }
    $this->_current_headers[] = array_map('trim', [$header[0], $header[1]]);
    return $length;
  }

  public static function error_string_from_code($code) {
    switch($code) {
      case 0:
        return '';
      case CURLE_COULDNT_RESOLVE_HOST:
        return 'dns_error';
      case CURLE_COULDNT_CONNECT:
        return 'connect_error';
      case CURLE_OPERATION_TIMEDOUT:
        return 'timeout';
      case CURLE_SSL_CONNECT_ERROR:
        return 'ssl_error';
      case CURLE_SSL_CERTPROBLEM:
        return 'ssl_cert_error';
      case CURLE_SSL_CIPHER:
        return 'ssl_unsupported_cipher';
      case CURLE_SSL_CACERT:
        return 'ssl_cert_error';
      case CURLE_TOO_MANY_REDIRECTS:
        return 'too_many_redirects';
      default:
        return 'unknown';
    }
  }
}
