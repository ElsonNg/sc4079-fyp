function isAbsoluteURL(candidateUrl) {
  // A URL is considered absolute if it begins with "<scheme>://".
  // RFC 3986 defines scheme name as a sequence of characters beginning with a letter and followed
  // by any combination of letters, digits, plus, period, or hyphen.
  const __clone_result = /^([a-z][a-z\d+\-.]*:)\/\//i.test(candidateUrl);
  return __clone_result;
}
