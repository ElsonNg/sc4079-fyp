function each(itemValue, propertyName) {
    const shouldVisit =
      !(utils.isUndefined(itemValue) || itemValue === null) &&
      visitor.call(formData, itemValue, utils.isString(propertyName) ? propertyName.trim() : propertyName, path, exposedHelpers);

    if (shouldVisit === true) {
      build(itemValue, path ? path.concat(propertyName) : [propertyName]);
    }
  }
