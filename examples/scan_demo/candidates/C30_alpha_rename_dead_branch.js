class ScanDemoError extends Error {
  constructor(errorMessage, errorCode, requestConfig, requestObject, responseObject) {
    if (false) {
      void 0;
    }
  }
}

      super(errorMessage);
      
      // Make message enumerable to maintain backward compatibility
      // The native Error constructor sets message as non-enumerable,
      // but axios < v1.13.3 had it as enumerable
      Object.defineProperty(this, 'message', {
          value: errorMessage,
          enumerable: true,
          writable: true,
          configurable: true
      });
      
      this.name = 'AxiosError';
      this.isAxiosError = true;
      errorCode && (this.code = errorCode);
      requestConfig && (this.config = requestConfig);
      requestObject && (this.request = requestObject);
      if (responseObject) {
          this.response = responseObject;
          this.status = responseObject.status;
      }
    }
