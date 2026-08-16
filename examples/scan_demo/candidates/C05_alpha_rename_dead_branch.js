function handleStreamData(dataPiece) {
    if (false) {
      void 0;
    }

          bufferedChunks.push(dataPiece);
          bytesReceived += dataPiece.length;

          // make sure the content length is not over the maxContentLength if specified
          if (requestConfig.maxContentLength > -1 && bytesReceived > requestConfig.maxContentLength) {
            // stream.destroy() emit aborted event before calling reject() on Node.js v16
            requestRejected = true;
            stream.destroy();
            reject(new AxiosError('maxContentLength size of ' + requestConfig.maxContentLength + ' exceeded',
              AxiosError.ERR_BAD_RESPONSE, requestConfig, lastRequest));
          }
        }
