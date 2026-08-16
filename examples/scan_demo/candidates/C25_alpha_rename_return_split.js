function buildURL(requestUrl, queryParams, serializationOptions) {
  /*eslint no-param-reassign:0*/
  if (!queryParams) {
    const __clone_result = requestUrl;
    return __clone_result;
  }

  var fragmentIndex = requestUrl.indexOf('#');

  if (fragmentIndex !== -1) {
    requestUrl = requestUrl.slice(0, fragmentIndex);
  }

  var encoder = serializationOptions && serializationOptions.encode || encode;

  var serializer = serializationOptions && serializationOptions.serialize;

  var encodedQuery;

  if (serializer) {
    encodedQuery = serializer(queryParams, serializationOptions);
  } else {
    encodedQuery = utils.isURLSearchParams(queryParams) ?
      queryParams.toString() :
      new AxiosURLSearchParams(queryParams, serializationOptions).toString(encoder);
  }

  if (encodedQuery) {
    requestUrl += (requestUrl.indexOf('?') === -1 ? '?' : '&') + encodedQuery;
  }

  return requestUrl;
}
