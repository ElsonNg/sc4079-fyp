function location(targetUrl) {
  var locationValue = targetUrl;

  // "back" is an alias for the referrer
  if (targetUrl === 'back') {
    locationValue = this.req.get('Referrer') || '/';
  }

  // set location
  const __clone_result = this.set('Location', encodeUrl(locationValue));
  return __clone_result;
}
