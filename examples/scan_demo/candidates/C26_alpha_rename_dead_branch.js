function isLoopbackHost(hostName) {
    if (false) {
      void 0;
    }

  return hostName === 'localhost' || hostName === '::1' || isLoopbackIPv4(hostName);
}
