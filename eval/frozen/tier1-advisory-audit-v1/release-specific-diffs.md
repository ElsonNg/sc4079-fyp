# Historical release-specific source pairs

Each historical snippet matches its Tier 1 target hash. These are release-source comparisons; no exploit is executed.

## GHSA-8xwg-wv7v-4vqp

```diff
--- 
+++ 
@@ -1,5 +1,5 @@
 (...args) => {
-    if (guest.getWebPreferences().nativeWindowOpen === true) {
+    if (guest.getLastWebPreferences().nativeWindowOpen === true) {
       const embedder = getEmbedder(guestInstanceId)
       if (embedder != null) {
         embedder.emit('-add-new-contents', ...args)
```

## GHSA-fmh4-wcc4-5jm3

```diff
--- 
+++ 
@@ -26,8 +26,13 @@
 				);
 			}
 
+			// Email-string equality is not ownership proof: a session whose user.email
+			// matches the invitation but has not been verified must not be treated as
+			// the invitation recipient. Gate is on by default; apps that intentionally
+			// allow unverified accept can opt out with `requireEmailVerificationOnInvitation: false`.
+			// FIXME(next-minor): drop the option and make the gate unconditional.
 			if (
-				ctx.context.orgOptions.requireEmailVerificationOnInvitation &&
+				(ctx.context.orgOptions.requireEmailVerificationOnInvitation ?? true) &&
 				!session.user.emailVerified
 			) {
 				throw APIError.from(
```

## GHSA-fph2-r4qg-9576

```diff
--- 
+++ 
@@ -4,13 +4,16 @@
           const op = this._getCLPOperation(subscription.query);
           let res: any = {};
           try {
-            await this._matchesCLP(
+            const matchesCLP = await this._matchesCLP(
               classLevelPermissions,
               message.currentParseObject,
               client,
               requestId,
               op
             );
+            if (matchesCLP === false) {
+              return null;
+            }
             const isMatched = await this._matchesACL(acl, client, requestId);
             if (!isMatched) {
               return null;
```

## GHSA-m983-v2ff-wq65

```diff
--- 
+++ 
@@ -1,4 +1,6 @@
 async requestId => {
+          // Deep-clone shared object so each concurrent callback works on its own copy
+          let localDeletedParseObject = JSON.parse(JSON.stringify(deletedParseObject));
           const acl = message.currentParseObject.getACL();
           // Check CLP
           const op = this._getCLPOperation(subscription.query);
@@ -21,7 +23,7 @@
             res = {
               event: 'delete',
               sessionToken: client.sessionToken,
-              object: deletedParseObject,
+              object: localDeletedParseObject,
               clients: this.clients.size,
               subscriptions: this.subscriptions.size,
               useMasterKey: client.hasMasterKey,
@@ -43,9 +45,9 @@
               return;
             }
             if (res.object && typeof res.object.toJSON === 'function') {
-              deletedParseObject = toJSONwithObjects(res.object, res.object.className || className);
+              localDeletedParseObject = toJSONwithObjects(res.object, res.object.className || className);
             }
-            res.object = deletedParseObject;
+            res.object = localDeletedParseObject;
             await this._filterSensitiveData(
               classLevelPermissions,
               res,
@@ -54,8 +56,7 @@
               op,
               subscription.query
             );
-            deletedParseObject = res.object;
-            client.pushDelete(requestId, deletedParseObject);
+            client.pushDelete(requestId, res.object);
           } catch (e) {
             const error = resolveError(e);
             Client.pushError(client.parseWebSocket, error.code, error.message, false, requestId);
```

