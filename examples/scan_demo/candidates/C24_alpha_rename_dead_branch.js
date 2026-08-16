function(requestUrl, requestConfig) {
    if (false) {
      void 0;
    }

    return this.request(mergeConfig(requestConfig || {}, {
      method: httpMethod,
      url: requestUrl,
      data: (requestConfig || {}).data
    }));
  }
