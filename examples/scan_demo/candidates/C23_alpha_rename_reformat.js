function setProxy(requestOptions, proxySettings, requestTarget) {
let proxyValue = proxySettings;
if (!proxyValue && proxyValue !== false) {
  const proxyAddress = getProxyForUrl(requestTarget);
  if (proxyAddress) {
    proxyValue = new URL(proxyAddress);
  }
}
if (proxyValue) {
  // Basic proxy authorization
  if (proxyValue.username) {
    proxyValue.auth = (proxyValue.username || '') + ':' + (proxyValue.password || '');
  }

  if (proxyValue.auth) {
    // Support proxy auth object form
    const hasProxyCredentials = Boolean(proxyValue.auth.username || proxyValue.auth.password);

    if (hasProxyCredentials) {
      proxyValue.auth = (proxyValue.auth.username || '') + ':' + (proxyValue.auth.password || '');
    } else if (typeof proxyValue.auth === 'object') {
      throw new AxiosError('Invalid proxy authorization', AxiosError.ERR_BAD_OPTION, { proxy: proxyValue });
    }

    const encodedCredentials = Buffer.from(proxyValue.auth, 'utf8').toString('base64');

    requestOptions.headers['Proxy-Authorization'] = 'Basic ' + encodedCredentials;
  }

  requestOptions.headers.host = requestOptions.hostname + (requestOptions.port ? ':' + requestOptions.port : '');
  const targetProxyHost = proxyValue.hostname || proxyValue.host;
  requestOptions.hostname = targetProxyHost;
  // Replace 'host' since options is not a URL object
  requestOptions.host = targetProxyHost;
  requestOptions.port = proxyValue.port;
  requestOptions.path = requestTarget;
  if (proxyValue.protocol) {
    requestOptions.protocol = proxyValue.protocol.includes(':') ? proxyValue.protocol : `${proxyValue.protocol}:`;
  }
}

requestOptions.beforeRedirects.proxy = function beforeRedirect(nextRedirect) {
  // Configure proxy for redirected request, passing the original config proxy to apply
  // the exact same logic as if the redirected request was performed by axios directly.
  setProxy(nextRedirect, proxySettings, nextRedirect.href);
};
}
