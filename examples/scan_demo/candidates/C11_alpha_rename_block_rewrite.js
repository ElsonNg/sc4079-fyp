function build(inputValue, pathSegments) {
    if (utils.isUndefined(inputValue)) {
      return;
    }

    if (stack.indexOf(inputValue) !== -1) {
      throw Error('Circular reference detected in ' + pathSegments.join('.'));
    }

    stack.push(inputValue);

    utils.forEach(inputValue, function each(itemValue, propertyName) {
      const shouldVisit =
        !(utils.isUndefined(itemValue) || itemValue === null) &&
        visitor.call(formData, itemValue, utils.isString(propertyName) ? propertyName.trim() : propertyName, pathSegments, exposedHelpers);

      if (shouldVisit === true) {
        build(itemValue, pathSegments ? pathSegments.concat(propertyName) : [propertyName]);
      }
    });

    stack.pop();
  }
