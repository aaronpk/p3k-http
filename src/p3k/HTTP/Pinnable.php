<?php
namespace p3k\HTTP;

// A transport that can be held to what safe mode checked: only http and
// https, no redirects of its own, and connections only to the addresses that
// were vetted. HTTP calls pin_addresses() before each request in safe mode
// and pin_addresses(null) after it.

interface Pinnable {

  /**
   * @param array|null $resolve "host:port:address[,address...]" entries, as
   *                            for CURLOPT_RESOLVE; null lifts the restriction.
   */
  public function pin_addresses($resolve);

}
