<?php
namespace p3k\HTTP;

// Decides whether a URL may be fetched when safe mode is on: http or https
// only, and a host whose every address is on the public internet (unless the
// host or the address is allowed explicitly). The addresses that were checked
// are returned so a transport can connect to exactly those, which defeats
// DNS rebinding between the check and the connection.

class Guard {

  // Hosts written as anything other than a plain dotted quad, such as
  // 2130706433, 0x7f.1 or 0177.0.0.1, are ones curl and the resolver would
  // read as an IP address. Refuse them rather than guess which one.
  const NUMERIC_HOST = '/^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+))*\.?$/i';

  // Addresses that are not on the public internet: the IANA IPv4 and IPv6
  // special-purpose registries, plus multicast. Listed here rather than
  // left to FILTER_FLAG_GLOBAL_RANGE, which needs PHP 8.2, so that every
  // PHP version refuses the same addresses.
  const NON_PUBLIC = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001::/23',
    '2001:db8::/32', '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
  ];

  private $_allow_hosts = [];
  private $_allow_cidrs = [];
  private $_resolver;

  /**
   * @param array $allow Hostnames, IP addresses or CIDR ranges that may be
   *                     reached even though they are not public.
   * @param callable|null $resolver fn(string $host): string[] of addresses;
   *                     defaults to the system resolver. Tests pass their own.
   */
  public function __construct(array $allow=[], $resolver=null) {
    foreach($allow as $entry) {
      $entry = strtolower(trim($entry));
      if($entry === '')
        continue;
      if(strpos($entry, '/') !== false || filter_var(trim($entry, '[]'), FILTER_VALIDATE_IP))
        $this->_allow_cidrs[] = strpos($entry, '/') !== false ? $entry : trim($entry, '[]') . (strpos($entry, ':') !== false ? '/128' : '/32');
      else
        $this->_allow_hosts[] = rtrim($entry, '.');
    }
    $this->_resolver = $resolver ?: [self::class, 'resolve'];
  }

  /**
   * @return array Either ['host' => ..., 'port' => ..., 'addresses' => [...]]
   *               or ['error' => 'blocked_url'|'dns_error', 'error_description' => ...]
   */
  public function check($url) {
    $parts = parse_url($url);
    if($parts === false || !isset($parts['scheme']) || !isset($parts['host']) || $parts['host'] === '')
      return self::_error('blocked_url', 'The URL is not a valid absolute URL');

    $scheme = strtolower($parts['scheme']);
    if($scheme !== 'http' && $scheme !== 'https')
      return self::_error('blocked_url', 'Only http and https URLs can be fetched');

    $host = strtolower($parts['host']);
    $port = isset($parts['port']) ? (int)$parts['port'] : ($scheme === 'https' ? 443 : 80);

    if($host[0] === '[') {
      $literal = substr($host, 1, -1);
      if(!filter_var($literal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
        return self::_error('blocked_url', 'The URL has an invalid IPv6 address');
      $addresses = [$literal];
    } elseif(filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      $addresses = [$host];
    } elseif(preg_match(self::NUMERIC_HOST, $host)) {
      return self::_error('blocked_url', 'The URL\'s host is an IP address in an unusual form');
    } else {
      $addresses = call_user_func($this->_resolver, rtrim($host, '.'));
      if(!$addresses)
        return self::_error('dns_error', 'Could not resolve ' . $host);
    }

    $hostAllowed = in_array(rtrim($host, '.'), $this->_allow_hosts, true);
    foreach($addresses as $address) {
      if(!$hostAllowed && !$this->_address_allowed($address))
        return self::_error('blocked_url', $host . ' resolves to ' . $address . ', which is not a public address');
    }

    return ['host' => $host, 'port' => $port, 'addresses' => array_values($addresses)];
  }

  /** Every IPv4 and IPv6 address the system resolver knows for a host. */
  public static function resolve($host) {
    $addresses = gethostbynamel($host) ?: [];
    $records = @dns_get_record($host, DNS_AAAA);
    foreach($records ?: [] as $record) {
      if(isset($record['ipv6']))
        $addresses[] = $record['ipv6'];
    }
    return array_values(array_unique($addresses));
  }

  /** Whether an address is on the public internet, looking inside IPv6 forms that carry an IPv4 address. */
  public static function is_public($address) {
    if(!filter_var($address, FILTER_VALIDATE_IP))
      return false;

    foreach(self::NON_PUBLIC as $cidr) {
      if(self::in_cidr($address, $cidr))
        return false;
    }

    $embedded = self::_embedded_ipv4($address);
    if($embedded !== null)
      return self::is_public($embedded);

    return true;
  }

  public static function in_cidr($address, $cidr) {
    list($subnet, $bits) = array_pad(explode('/', $cidr, 2), 2, null);
    $a = @inet_pton($address);
    $s = @inet_pton($subnet);
    if($a === false || $s === false || strlen($a) !== strlen($s))
      return false;
    $bits = $bits === null ? strlen($a) * 8 : (int)$bits;
    $bytes = intdiv($bits, 8);
    if(substr($a, 0, $bytes) !== substr($s, 0, $bytes))
      return false;
    $rest = $bits % 8;
    if($rest === 0)
      return true;
    $mask = chr((0xff << (8 - $rest)) & 0xff);
    return ($a[$bytes] & $mask) === ($s[$bytes] & $mask);
  }

  private function _address_allowed($address) {
    foreach($this->_allow_cidrs as $cidr) {
      if(self::in_cidr($address, $cidr))
        return true;
    }
    return self::is_public($address);
  }

  // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses reach an IPv4
  // address, which must be public too.
  private static function _embedded_ipv4($address) {
    $bin = @inet_pton($address);
    if($bin === false || strlen($bin) !== 16)
      return null;
    if(self::in_cidr($address, '64:ff9b::/96'))
      return inet_ntop(substr($bin, 12, 4));
    if(self::in_cidr($address, '2002::/16'))
      return inet_ntop(substr($bin, 2, 4));
    return null;
  }

  private static function _error($code, $description) {
    return ['error' => $code, 'error_description' => $description];
  }
}
