function ContentTypeParser (bodyLimit, onProtoPoisoning, onConstructorPoisoning) {
  this[kDefaultJsonParse] = getDefaultJsonParser(onProtoPoisoning, onConstructorPoisoning);
  // using a map instead of a plain object to avoid prototype hijack attacks
  let customParsers = new Map();
  customParsers.set('application/json', new Parser(true, false, bodyLimit, this[kDefaultJsonParse]));
  customParsers.set('text/plain', new Parser(true, false, bodyLimit, defaultPlainTextParser));
  this.customParsers = customParsers;
  this.parserList = [
    new ParserListItem('application/json'),
    new ParserListItem('text/plain')
  ];
  this.parserRegExpList = [];
  this.cache = lru(100);
}

function deleteLength(e, t, r) {
    if ((e.method === "DELETE" || e.method === "OPTIONS") && typeof e.headers["content-length"] === "undefined" && typeof e.headers["transfer-encoding"] === "undefined") {
        e.headers["content-length"] = "0";
    }
}

function clampNumber(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}
