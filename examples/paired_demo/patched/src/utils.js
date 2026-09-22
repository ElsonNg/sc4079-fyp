function clone(inputObject) {
  const targetObject = create(null);

  let key;
  for (key in inputObject) {
    if (apply(hasOwnProperty, inputObject, [key]) === true) {
      targetObject[key] = inputObject[key];
    }
  }

  return targetObject;
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
