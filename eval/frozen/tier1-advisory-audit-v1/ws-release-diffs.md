# ws historical release source pairs

The four source files were fetched from immutable release commits and are hash-pinned in the audit script. The anonymous callback in each file matches the labelled Tier 1 target hash.

## 1.1.4 → 1.1.5

Source: https://raw.githubusercontent.com/websockets/ws/19106a14d1782bed6f3b12a612e1a73a4970fdbe/lib/Extensions.js and https://raw.githubusercontent.com/websockets/ws/24edef58a0aab05e8220f76bd2377614dd4eee85/lib/Extensions.js

```diff
--- 
+++ 
@@ -1,7 +1,13 @@
 function(v) {
     var params = v.split(';');
     var token = params.shift().trim();
-    var paramsList = extensions[token] = extensions[token] || [];
+
+    if (extensions[token] === undefined) {
+      extensions[token] = [];
+    } else if (!extensions.hasOwnProperty(token)) {
+      return;
+    }
+
     var parsedParams = {};
 
     params.forEach(function(param) {
@@ -19,8 +25,13 @@
           value = value.slice(0, value.length - 1);
         }
       }
-      (parsedParams[key] = parsedParams[key] || []).push(value);
+
+      if (parsedParams[key] === undefined) {
+        parsedParams[key] = [value];
+      } else if (parsedParams.hasOwnProperty(key)) {
+        parsedParams[key].push(value);
+      }
     });
 
-    paramsList.push(parsedParams);
+    extensions[token].push(parsedParams);
   }
```

## 3.3.0 → 3.3.1

Source: https://raw.githubusercontent.com/websockets/ws/56f80625399de02abfe6c0d718ea5a8939969318/lib/Extensions.js and https://raw.githubusercontent.com/websockets/ws/70eb3b2f6284a361768ea518acb072d13986dade/lib/Extensions.js

```diff
--- 
+++ 
@@ -1,7 +1,13 @@
 (v) => {
     const params = v.split(';');
     const token = params.shift().trim();
-    const paramsList = extensions[token] = extensions[token] || [];
+
+    if (extensions[token] === undefined) {
+      extensions[token] = [];
+    } else if (!extensions.hasOwnProperty(token)) {
+      return;
+    }
+
     const parsedParams = {};
 
     params.forEach((param) => {
@@ -20,8 +26,13 @@
           value = value.slice(0, value.length - 1);
         }
       }
-      (parsedParams[key] = parsedParams[key] || []).push(value);
+
+      if (parsedParams[key] === undefined) {
+        parsedParams[key] = [value];
+      } else if (parsedParams.hasOwnProperty(key)) {
+        parsedParams[key].push(value);
+      }
     });
 
-    paramsList.push(parsedParams);
+    extensions[token].push(parsedParams);
   }
```

