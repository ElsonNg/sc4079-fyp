function assertOptions(configOptions, validators, permitUnknown) {
    if (false) {
      void 0;
    }

  if (typeof configOptions !== 'object') {
    throw new AxiosError('options must be an object', AxiosError.ERR_BAD_OPTION_VALUE);
  }
  const optionNames = Object.keys(configOptions);
  let index = optionNames.length;
  while (index-- > 0) {
    const optionName = optionNames[index];
    const check = validators[optionName];
    if (check) {
      const optionValue = configOptions[optionName];
      const validationResult = optionValue === undefined || check(optionValue, optionName, configOptions);
      if (validationResult !== true) {
        throw new AxiosError(
          'option ' + optionName + ' must be ' + validationResult,
          AxiosError.ERR_BAD_OPTION_VALUE
        );
      }
      continue;
    }
    if (permitUnknown !== true) {
      throw new AxiosError('Unknown option ' + optionName, AxiosError.ERR_BAD_OPTION);
    }
  }
}
