<?php
namespace p3k;

class HTTP {

  public $_timeout = 4;
  public $_max_redirects = 8;

  private $_transport;
  private $_user_agent;
  private $_guard = null;

  public function __construct($user_agent=null, ?HTTP\Transport $transport=null) {
    if($user_agent) {
      $this->_user_agent = $user_agent;
    }
    if(!$transport) {
      $this->_transport = new HTTP\Curl();
    } else {
      $this->set_transport($transport);
    }
  }

  public function set_user_agent($ua) {
    $this->_user_agent = $ua;
  }

  public function set_max_redirects($max) {
    $this->_max_redirects = $max;
  }

  public function set_timeout($timeout) {
    $this->_timeout = $timeout;
  }

  public function set_transport(HTTP\Transport $transport) {
    $this->_transport = $transport;
  }

  /**
   * Safe mode: only fetch http and https URLs whose host resolves to public
   * addresses, follow redirects one at a time so every hop is checked, and
   * drop credentials when a redirect leaves the original origin.
   *
   * @param bool          $enabled
   * @param array         $allow    Hostnames, IP addresses or CIDR ranges that
   *                                may be reached although they are private,
   *                                e.g. a development server on the LAN.
   * @param callable|null $resolver fn(string $host): string[]; the system
   *                                resolver when null. For tests.
   */
  public function set_safe_mode($enabled, array $allow=[], $resolver=null) {
    $this->_guard = $enabled ? new HTTP\Guard($allow, $resolver) : null;
  }

  public function safe_mode() {
    return $this->_guard !== null;
  }

  public function get($url, $headers=[]) {
    return $this->_request('get', $url, false, $headers);
  }

  public function post($url, $body, $headers=[]) {
    return $this->_request('post', $url, $body, $headers);
  }

  public function head($url, $headers=[]) {
    return $this->_request('head', $url, false, $headers);
  }

  public function put($url, $body, $headers=[]) {
    return $this->_request('put', $url, $body, $headers);
  }

  private function _request($method, $url, $body, $headers) {
    $this->_transport->set_timeout($this->_timeout);
    if($this->_user_agent) {
      $headers[] = 'User-Agent: ' . $this->_user_agent;
    }

    if($this->_guard === null) {
      $this->_transport->set_max_redirects($this->_max_redirects);
      return $this->_build_response($this->_send($method, $url, $body, $headers));
    }

    $this->_transport->set_max_redirects(0);
    $redirects = $this->_max_redirects;

    while(true) {
      $check = $this->_guard->check($url);
      if(isset($check['error'])) {
        return $this->_build_response([
          'code' => 0,
          'header' => '',
          'body' => false,
          'error' => $check['error'],
          'error_description' => $check['error_description'],
          'url' => $url,
          'debug' => '',
        ]);
      }

      $pinnable = $this->_transport instanceof HTTP\Pinnable;
      if($pinnable) {
        $this->_transport->pin_addresses(array_map(function($address) use($check) {
          return $check['host'] . ':' . $check['port'] . ':' . (strpos($address, ':') !== false ? '[' . $address . ']' : $address);
        }, $check['addresses']));
      }
      try {
        $response = $this->_build_response($this->_send($method, $url, $body, $headers));
      } finally {
        if($pinnable)
          $this->_transport->pin_addresses(null);
      }

      $location = in_array((int)$response['code'], [301, 302, 303, 307, 308], true) ? ($response['headers']['Location'] ?? null) : null;
      if(is_array($location))
        $location = end($location);
      if(!is_string($location) || $location === '')
        return $response;

      if($redirects-- <= 0) {
        $response['error'] = 'too_many_redirects';
        $response['error_description'] = 'Stopped after ' . $this->_max_redirects . ' redirects';
        return $response;
      }

      $next = \Mf2\resolveUrl($url, $location);
      if(self::_origin($next) !== self::_origin($url)) {
        $headers = array_values(array_filter($headers, function($header) {
          return !preg_match('/^\s*(authorization|proxy-authorization|cookie)\s*:/i', $header);
        }));
      }
      $url = $next;
    }
  }

  private function _send($method, $url, $body, $headers) {
    if($method === 'post' || $method === 'put')
      return $this->_transport->{$method}($url, $body, $headers);
    return $this->_transport->{$method}($url, $headers);
  }

  private static function _origin($url) {
    $parts = parse_url($url);
    $scheme = strtolower($parts['scheme'] ?? '');
    $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
    return $scheme . '://' . strtolower($parts['host'] ?? '') . ':' . $port;
  }

  private function _build_response($response) {
    // Parses the HTTP headers and adds the "headers" and "rels" response keys
    $response['headers'] = self::_parse_headers($response['header']);
    $response['rels'] = \IndieWeb\http_rels($response['header']);
    return $response;
  }

  private static function _parse_headers($headers) {
    $retVal = [];
    $fields = explode("\r\n", preg_replace('/\x0D\x0A[\x09\x20]+/', ' ', $headers));
    foreach($fields as $field) {
      if(preg_match('/([^:]+): (.+)/m', $field, $match)) {
        $match[1] = preg_replace_callback('/(?<=^|[\x09\x20\x2D])./', function($m) {
          return strtoupper($m[0]);
        }, strtolower(trim($match[1])));
        // If there's already a value set for the header name being returned, turn it into an array and add the new value
        $match[1] = preg_replace_callback('/(?<=^|[\x09\x20\x2D])./', function($m) {
          return strtoupper($m[0]);
        }, strtolower(trim($match[1])));
        if(isset($retVal[$match[1]])) {
          if(!is_array($retVal[$match[1]]))
            $retVal[$match[1]] = [$retVal[$match[1]]];
          $retVal[$match[1]][] = $match[2];
        } else {
          $retVal[$match[1]] = trim($match[2]);
        }
      }
    }
    return $retVal;
  }
}
