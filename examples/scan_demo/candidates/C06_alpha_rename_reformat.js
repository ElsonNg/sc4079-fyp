function handlerStreamAborted() {
        if (requestRejected) {
          return;
        }
        incomingStream.destroy();
        reject(new AxiosError(
          'maxContentLength size of ' + requestConfig.maxContentLength + ' exceeded',
          AxiosError.ERR_BAD_RESPONSE,
          requestConfig,
          lastRequest
        ));
      }
