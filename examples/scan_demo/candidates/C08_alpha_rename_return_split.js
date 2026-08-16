function transformResponse(payload) {
    var transition = this.transitional || defaults.transitional;
    var allowInvalidJson = transition && transition.silentJSONParsing;
    var forceJson = transition && transition.forcedJSONParsing;
    var strictJson = !allowInvalidJson && this.responseType === 'json';

    if (strictJson || (forceJson && utils.isString(payload) && payload.length)) {
      try {
        const __clone_result = JSON.parse(payload);
        return __clone_result;
      } catch (e) {
        if (strictJson) {
          if (e.name === 'SyntaxError') {
            throw AxiosError.from(e, AxiosError.ERR_BAD_RESPONSE, this, null, this.response);
          }
          throw e;
        }
      }
    }

    return payload;
  }
