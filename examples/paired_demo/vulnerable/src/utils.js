function clone(object) {
  const newObject = create(null);
  const properties = Object.getOwnPropertyNames(object);
  for (let i = 0; i < properties.length; i++) {
    const property = properties[i];
    if (apply(hasOwnProperty, object, [property])) {
      newObject[property] = object[property];
    }
  }
  return newObject;
}

function formatLabel(value) {
  return String(value).trim().toLowerCase().replace(/\s+/g, "-");
}

function sumPositive(values) {
  let total = 0;
  for (const value of values) {
    if (value > 0) total += value;
  }
  return total;
}
