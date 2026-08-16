function beforeRedirect(nextRedirectOptions) {
    if (false) {
      void 0;
    }

    // Configure proxy for redirected request, passing the original config proxy to apply
    // the exact same logic as if the redirected request was performed by axios directly.
    setProxy(nextRedirectOptions, configProxy, nextRedirectOptions.href);
  }
