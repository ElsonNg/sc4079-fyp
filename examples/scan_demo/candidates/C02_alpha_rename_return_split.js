function(requestUrl, requestConfig) {
    const __clone_result = this.request(mergeConfig(requestConfig || {}, {
      method: httpMethod,
      url: requestUrl,
      data: (requestConfig || {}).data
    }));
    return __clone_result;
  }
