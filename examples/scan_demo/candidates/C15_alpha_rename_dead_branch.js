function setProxy(requestOptions, proxySettings, requestTarget) {
    if (false) {
      void 0;
    }

  var proxyValue = proxySettings;
  if (!proxyValue && proxyValue !== false) {
    var proxyAddress = getProxyForUrl(requestTarget);
    if (proxyAddress) {
      proxyValue = url.parse(proxyAddress);
      // replace 'host' since the proxy object is not a URL object
      proxyValue.host = proxyValue.hostname;
    }
  }
  if (proxyValue) {
    // Basic proxy authorization
    if (proxyValue.auth) {
      // Support proxy auth object form
      if (proxyValue.auth.username || proxyValue.auth.password) {
        proxyValue.auth = (proxyValue.auth.username || '') + ':' + (proxyValue.auth.password || '');
      }
      var encodedCredentials = Buffer
        .from(proxyValue.auth, 'utf8')
        .toString('base64');
      requestOptions.headers['Proxy-Authorization'] = 'Basic ' + encodedCredentials;
    }

    requestOptions.headers.host = requestOptions.hostname + (requestOptions.port ? ':' + requestOptions.port : '');
    requestOptions.hostname = proxyValue.host;
    requestOptions.host = proxyValue.host;
    requestOptions.port = proxyValue.port;
    requestOptions.path = requestTarget;
    if (proxyValue.protocol) {
      requestOptions.protocol = proxyValue.protocol;
    }
  }

  requestOptions.beforeRedirects.proxy = function beforeRedirect(nextRedirect) {
    // Configure proxy for redirected request, passing the original config proxy to apply
    // the exact same logic as if the redirected request was performed by axios directly.
    setProxy(nextRedirect, proxySettings, nextRedirect.href);
  };
}
