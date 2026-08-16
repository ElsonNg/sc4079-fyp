function location(targetUrl) {
  var locationValue = String(targetUrl);

  // "back" is an alias for the referrer
  if (targetUrl === 'back') {
    locationValue = this.req.get('Referrer') || '/';
  }

  var lowerLocation = locationValue.toLowerCase();
  var encodedLocation = encodeUrl(locationValue);
  if (lowerLocation.indexOf('https://') === 0 || lowerLocation.indexOf('http://') === 0) {
    try {
      var parsedLocation = urlParse(locationValue);
      var parsedEncodedLocation = urlParse(encodedLocation);
      // Because this can encode the host, check that we did not change the host
      if (parsedLocation.host !== parsedEncodedLocation.host) {
        // If the host changes after encodeUrl, return the original url
        const __clone_result = this.set('Location', locationValue);
        return __clone_result;
      }
    } catch (parseError) {
      // If parse fails, return the original url
      return this.set('Location', locationValue);
    }
  }

  // set location
  return this.set('Location', encodedLocation);
}
