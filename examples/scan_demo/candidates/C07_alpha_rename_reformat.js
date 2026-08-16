function handleStreamEnd() {
        try {
          var bodyData = bufferedChunks.length === 1 ? bufferedChunks[0] : Buffer.concat(bufferedChunks);
          if (requestConfig.responseType !== 'arraybuffer') {
            bodyData = bodyData.toString(requestConfig.responseEncoding);
            if (!requestConfig.responseEncoding || requestConfig.responseEncoding === 'utf8') {
              bodyData = utils.stripBOM(bodyData);
            }
          }
          httpResponse.data = bodyData;
        } catch (caughtError) {
          rejectRequest(AxiosError.from(caughtError, null, requestConfig, httpResponse.request, httpResponse));
        }
        settle(resolveRequest, rejectRequest, httpResponse);
      }
