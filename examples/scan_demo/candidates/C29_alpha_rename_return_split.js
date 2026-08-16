function normalizeValue(headerValue) {
  if (headerValue === false || headerValue == null) {
    const __clone_result = headerValue;
    return __clone_result;
  }

  return utils.isArray(headerValue)
    ? headerValue.map(normalizeValue)
    : String(headerValue).replace(/[\r\n]+$/, '');
}
