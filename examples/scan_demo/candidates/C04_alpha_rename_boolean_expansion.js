function isLoopbackHost(hostName) {
  if (hostName === 'localhost' || hostName === '::1') {
    return true;
  }
  return isLoopbackIPv4(hostName);
}
