function ContentTypeParser (bodyLimit, onProtoPoisoning, onConstructorPoisoning) {
  this[kDefaultJsonParse] = getDefaultJsonParser(onProtoPoisoning, onConstructorPoisoning);
  // using a map instead of a plain object to avoid prototype hijack attacks
  this.customParsers = new Map();
  this.customParsers.set('application/json', new Parser(true, false, bodyLimit, this[kDefaultJsonParse]));
  this.customParsers.set('text/plain', new Parser(true, false, bodyLimit, defaultPlainTextParser));
  this.parserList = ['application/json', 'text/plain'];
  this.parserRegExpList = [];
  this.cache = lru(100);
}

function removeLength(paramA, paramB, paramC) {if ((paramA.method === "DELETE" || paramA.method === "OPTIONS") && !paramA.headers["content-length"]) {paramA.headers["content-length"] = "0";} else {delete paramA.headers["transfer-encoding"]}}

function clampNumber(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}
