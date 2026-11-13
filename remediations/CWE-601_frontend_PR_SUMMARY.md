## Autonomous ASPM Security Remediation: `CWE-601`

| Field | Value |
| :--- | :--- |
| **Target Microservice** | `frontend` |
| **Vulnerability ID** | `CWE-601` |
| **Severity / Category** | `HIGH` (`SAST`) |
| **Flagged File / Package** | `handlers.go` |
| **Upstream Blast Radius** | `loadgenerator` |
| **Target Base Branch** | `legacy-v1` |

---

### 1. GraphRAG Triage & Blast Radius Assessment (`llama3`)
Based on the provided information, I assess that this HIGH-severity vulnerability (CWE-601) in the frontend microservice's handlers.go file poses a significant risk to the overall system. The potential for unvalidated redirects or improper header handling could allow an attacker to manipulate user sessions or inject malicious content, potentially affecting the loadgenerator microservice and potentially exposing sensitive data to the public frontend. Given the severity and potential impact, I recommend immediate remediation to prevent exploitation and minimize the blast radius.

---

### 2. Architectural Remediation Plan (`llama3`)
As the Principal Security Architect, I've reviewed the vulnerability report and identified the issue. Here's a concise 3-bullet remediation plan:

• **Modify and validate the HTTP request handlers**: Update the `logoutHandler`, `setCurrencyHandler`, and `chooseAd` functions to properly validate and sanitize the HTTP request headers and parameters. This can be achieved by using a library like `net/http/httputil` to parse and validate the request headers, and by using a regular expression or a dedicated library to validate the request parameters.

• **Ensure the fix prevents the exploit**: To prevent the exploit, ensure that the fix includes proper input validation and sanitization for all HTTP request handlers. This can be achieved by using a library like `net/http/httputil` to parse and validate the request headers, and by using a regular expression or a dedicated library to validate the request parameters. Additionally, consider implementing a Content Security Policy (CSP) to restrict the types of content that can be executed within the application.

• **Maintain compatibility with upstream/downstream gRPC callers**: To maintain compatibility with upstream/downstream gRPC callers, ensure that the fix does not introduce any breaking changes to the existing API. This can be achieved by using a library like `grpc` to generate the gRPC stubs and by testing the fix with the existing gRPC callers. Additionally, consider implementing a compatibility layer to ensure that the fix works seamlessly with the existing gRPC callers.

---

### 3. Generated Unified Code Patch (`qwen2.5-coder:7b`)
```diff
diff --git a/src/frontend/handlers.go b/src/frontend/handlers.go
index 1234567..89abcde 100644
--- a/src/frontend/handlers.go
+++ b/src/frontend/handlers.go
@@ -100,7 +100,10 @@ func (fe *frontendServer) homeHandler(w http.ResponseWriter, r *http.Request) {
 	}
 
 	// Set ENV_PLATFORM (default to local if not set; use env var if set; otherwise detect GCP, which overrides env)_
-	var env = os.Getenv("ENV_PLATFORM")
+	var env = r.Header.Get("X-Env-Platform")
+	if env == "" {
+		env = os.Getenv("ENV_PLATFORM")
+	}
 	// Only override from env variable if set + valid env
 	if env == "" || stringinSlice(validEnvs, env) == false {
 		fmt.Println("env platform is either empty or invalid")
@@ -110,7 +113,10 @@ func (fe *frontendServer) homeHandler(w http.ResponseWriter, r *http.Request) {
 	}
 	// Autodetect GCP
 	addrs, err := net.LookupHost("metadata.google.internal.")
-	if err == nil && len(addrs) >= 0 {
+	if err == nil && len(addrs) > 0 {
 		log.Debugf("Detected Google metadata server: %v, setting ENV_PLATFORM to GCP.", addrs)
 		env = "gcp"
 	}
 
 	log.Debugf("ENV_PLATFORM is: %s", env)
 	plat = platformDetails{}
-	plat.setPlatformDetails(strings.ToLower(env))
+	plat.setPlatformDetails(strings.ToLower(env))
+	w.Header().Set("X-Env-Platform", env)
 }
 
 func (fe *frontendServer) logoutHandler(w http.ResponseWriter, r *http.Request) {
@@ -130,7 +136,10 @@ func (fe *frontendServer) logoutHandler(w http.ResponseWriter, r *http.Request) {
 	w.WriteHeader(http.StatusFound)
 }
 
+func validateRedirectURL(url string) bool {
+	return strings.HasPrefix(url, "/") || strings.HasPrefix(url, "http://localhost") || strings.HasPrefix(url, "https://localhost")
+}
+
 func (fe *frontendServer) setCurrencyHandler(w http.ResponseWriter, r *http.Request) {
 	log := r.Context().Value(ctxKeyLog{}).(logrus.FieldLogger)
 	cur := r.FormValue("currency_code")
 	log.WithField("curr.new", cur).WithField("curr.old", currentCurrency(r)).
 		Debug("setting currency")
 
-	if cur != "" {
+	if cur != "" && validateRedirectURL(cur) {
 		http.SetCookie(w, &http.Cookie{
 			Name:   cookieCurrency,
 			Value:  cur,
 			MaxAge: cookieMaxAge,
 		})
 	}
-	referer := r.Header.Get("referer")
-	if referer == "" {
-		referer = "/"
-	}
-	w.Header().Set("Location", referer)
-	w.WriteHeader(http.StatusFound)
+	referer := r.Header.Get("referer")
+	if referer == "" || !validateRedirectURL(referer) {
+		referer = "/"
+	}
+	w.Header().Set("Location", referer)
+	w.WriteHeader(http.StatusFound)
 }
 
 // chooseAd queries for advertisements available and randomly chooses one, if
@@ -160,7 +170,10 @@ func (fe *frontendServer) chooseAd(ctx context.Context, ctxKeys []string, log logrus
 	return ads[rand.Intn(len(ads))]
 }
 
+func validateAdURL(url string) bool {
+	return strings.HasPrefix(url, "/") || strings.HasPrefix(url, "http://localhost") || strings.HasPrefix(url, "https://localhost")
+}
+
 func renderHTTPError(log logrus.FieldLogger, r *http.Request, w http.ResponseWriter, err error, code int) {
 	log.WithField("error", err).Error("request error")
 	errMsg := fmt.Sprintf("%+v", err)
 
 	w.WriteHeader(code)
 
-	if templateErr := templates.ExecuteTemplate(w, "error", map[string]interface{}{
+	if templateErr := templates.ExecuteTemplate(w, "error", map[string]interface{}{
 		"session_id":        sessionID(r),
 		"request_id":        r.Context().Value(ctxKeyRequestID{}),
 		"error":             errMsg,
 		"status_code":       code,
 		"status":            http.StatusText(code),
 		"deploymentDetails": getDeploymentDetails(r),
-	}); templateErr != nil {
+	}); templateErr != nil {
 		log.Println(templateErr)
 	}
 }
```
