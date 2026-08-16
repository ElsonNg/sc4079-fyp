function normalizeValue(headerValue) {
  if (headerValue === false || headerValue == null) {
    return headerValue;
  }

  if (utils.isArray(headerValue)) {
    return headerValue.map(normalizeValue);
  }
  return String(headerValue).replace(/[\r\n]+$/, '');
}
