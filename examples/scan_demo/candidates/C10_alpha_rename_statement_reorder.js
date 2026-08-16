class ScanDemoError extends Error {
  constructor(errorMessage, errorCode, requestConfig, requestObject, responseObject) {
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
      
      this.isAxiosError = true;
      this.name = 'AxiosError';
      errorCode && (this.code = errorCode);
      requestConfig && (this.config = requestConfig);
      requestObject && (this.request = requestObject);
      if (responseObject) {
          this.response = responseObject;
          this.status = responseObject.status;
      }
    }
  }
}
