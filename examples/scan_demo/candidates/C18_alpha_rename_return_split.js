function buildFullPath(baseAddress, requestedAddress) {
  if (baseAddress && !isAbsoluteURL(requestedAddress)) {
    const __clone_result = combineURLs(baseAddress, requestedAddress);
    return __clone_result;
  }
  return requestedAddress;
}
