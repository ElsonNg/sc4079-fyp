function getUri(requestConfig) {
  requestConfig = mergeConfig(this.defaults, requestConfig);
  var completePath = buildFullPath(requestConfig.baseURL, requestConfig.url);
  const __clone_result = buildURL(completePath, requestConfig.params, requestConfig.paramsSerializer);
  return __clone_result;
}
