package burp;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.tomitribe.auth.signatures.MissingRequiredHeaderException;
import org.tomitribe.auth.signatures.PEM;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class Signing {

    static boolean DEBUG = false;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    static ConfigSettings globalSettings;

    public Signing(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        globalSettings = new ConfigSettings();
    }

    /**
     * This method checks whether this extension is enabled for the Burp Suite tool
     * @param toolFlag The <code>IBurpExtenderCallbacks</code> tool to check if this extension is enabled in the settings
     * @return Returns true if the extension is enabled for this tool, false if not.
     *         The extension is enabled by default for Repeater, Intruder, and Scanner.
     */
    public static boolean enabledForTool(int toolFlag) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            if (Signing.callbacks.loadExtensionSetting("enableProxy") != null) {
                return Signing.callbacks.loadExtensionSetting("enableProxy").equals("true");
            } else {
                return false; // default value: disabled for the proxy tool
            }
        } else if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) {
            if (Signing.callbacks.loadExtensionSetting("enableScanner") != null) {
                return Signing.callbacks.loadExtensionSetting("enableScanner").equals("true");
            } else {
                return true; // default value: enabled for the scanner tool
            }
        } else if (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
            if (Signing.callbacks.loadExtensionSetting("enableIntruder") != null) {
                return Signing.callbacks.loadExtensionSetting("enableIntruder").equals("true");
            } else {
                return true; // default value: enabled for the intruder tool
            }
        } else if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
            if (Signing.callbacks.loadExtensionSetting("enableRepeater") != null) {
                return Signing.callbacks.loadExtensionSetting("enableRepeater").equals("true");
            } else {
                return true; // default value: enabled for the repeater tool
            }
        } else {
            return false;
        }
    }

    /**
     * This method signs the request.
     * @param messageInfo This parameter contains the request to sign.
     * @return The signed request.
     */
    public static byte[] signRequest(IHttpRequestResponse messageInfo) {

        HttpRequestBase request;
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        List<String> headers = requestInfo.getHeaders();
        String body = "";
        String keyId = globalSettings.getString("keyId");

        // e.g. String privateKeyFilename = "/home/${USER}/private-key.pem";
        String privateKeyFilename = globalSettings.getString("Private key file name and path");
        PrivateKey privateKey = loadPrivateKey(privateKeyFilename);
        RequestSigner signer = new RequestSigner(keyId, privateKey);

        String url = requestInfo.getUrl().toString();
        log(" --- NEW REQUEST ---\nDEBUG: Input URL   : " + url);

        String query = requestInfo.getUrl().getQuery();
        // URL decode to avoid double URL encoding later
        if (query != null) {
            query = URLDecoder.decode(query, StandardCharsets.UTF_8);

            // get port, but do not include it if its 80 or 443
            String port_str = "";
            if (requestInfo.getUrl().getPort() != -1) {
                int port = requestInfo.getUrl().getPort();
                if (port != 80 && port != 443) {
                    port_str = ":" + port;
                }
            }

            url = requestInfo.getUrl().getProtocol() + "://" +
                    requestInfo.getUrl().getHost() +
                    port_str +
                    requestInfo.getUrl().getPath() + "?" +
                    query;

            log("DEBUG: Decoded URL : " + url);
        }

        // Make sure the query is properly URL encoded
        try {
            URL jurl = new URL(url);
            String nullFragment = null;

            // get port, but do not include it if its 80 or 443
            String port_str = "";
            if (jurl.getPort() != -1) {
                int port = jurl.getPort();
                if (port != 80 && port != 443) {
                    port_str = ":" + port;
                }
            }
            URI uri = new URI(jurl.getProtocol(), jurl.getHost() + port_str, jurl.getPath(), jurl.getQuery(), nullFragment);
            url = uri.toString();
        } catch (MalformedURLException e) {
            err("URL " + url + " is malformed");
        } catch (URISyntaxException e) {
            err("URI " + url + " is malformed");
        }

        log("DEBUG: Encoded URL : " + url);

        // Hack for OCI
        if ( url.contains("oraclecloud.com/") ) {
            url = url.replaceAll(":", "%3A");
        }
        // we need some additional URL encoding for specific characters
        url = url.replaceAll("https%3A//", "https://");
        url = url.replaceAll("http%3A//", "http://");
        url = url.replaceAll(",", "%2C");
        //url = url.replaceAll("@", "%40");
        //url = url.replaceAll("\"","%22"); // encode double quotes (") in query parameters

        log("DEBUG: Encoded URL2: " + url);

        if (requestInfo.getMethod().equals("POST")) {
            request = new HttpPost(url);
        } else if (requestInfo.getMethod().equals("PUT")) {
            request = new HttpPut(url);
        } else if (requestInfo.getMethod().equals("GET")) {
            request = new HttpGet(url);
        } else if (requestInfo.getMethod().equals("HEAD")) {
            request = new HttpHead(url);
        } else if (requestInfo.getMethod().equals("DELETE")) {
            request = new HttpDelete(url);
        } else {
            err("ERROR: Unknown Method: " + requestInfo.getMethod());
            request = new HttpGet(url);
        }

        // add HTTP request body for POST and PUT requests
        if (requestInfo.getMethod().equals("POST") || requestInfo.getMethod().equals("PUT")) {
            HttpEntity entity;
            byte[] requestByte = messageInfo.getRequest();
            byte[] bodyByte = Arrays.copyOfRange(requestByte, requestInfo.getBodyOffset(), requestByte.length);
            try {
                body = new String(bodyByte);
                entity = new StringEntity(body);
                log("<BODY>" + body + "</BODY>");
                if (requestInfo.getMethod().equals("POST")) {
                    ((HttpPost) request).setEntity(entity);
                } else {
                    ((HttpPut) request).setEntity(entity);
                }
            } catch (UnsupportedEncodingException | ClassCastException e) {
                err("ERROR creating HTTP POST/PUT request body.");
                e.printStackTrace();
            }
        }

        log("DEBUG: OLD HEADERS START");
        // 'headers' includes the URL (e.g. GET, POST, etc.) as the first element
        String headerZero = headers.get(0); // save the URL for later
        headers.remove(0); // remove the URL (first element)

        String header_name = globalSettings.getString("Header Name").toLowerCase();

        // add all HTTP request headers except 'x-date' and the configured 'Header Name' value
        for (String header : headers) {
            log(header);
            if (header.toLowerCase().startsWith(header_name)) { // e.g. signature, authorization
                continue; // skip the configured header containing the signature/key
            } else if (header.toLowerCase().startsWith("x-date")) {
                continue; // skip "x-date" header
            } else {
                String[] headerPair = header.split(":", 2);
                request.addHeader(headerPair[0].trim(), headerPair[1].trim());
            }
        }
        log("DEBUG: OLD HEADERS END");

        signer.signRequest(request, header_name);

        // copy the HTTP headers from the signed request to newHeader
        List<String> newHeaders = new ArrayList<>();
        org.apache.http.Header[] tmpheaders = request.getAllHeaders();
        log("DEBUG: NEW HEADERS START");
        newHeaders.add(headerZero);
        for (org.apache.http.Header header : tmpheaders) {
            newHeaders.add(header.getName() + ": " + header.getValue());
            log(header.getName() + ": " + header.getValue());
        }
        log("DEBUG: NEW HEADERS END");

        return helpers.buildHttpMessage(newHeaders, body.getBytes());
    }

    /**
     * Logging a message for debugging purposes to stdout. Only logs when DEBUG is set to true.
     * @param message   The message to be logged
     */
    static void log(String message) {
        if (DEBUG) {
            callbacks.printOutput(message);
        }
    }

    /**
     * Logging an error message for debugging purposes to stderr.
     * @param message   The message to be logged
     */
    public static void err(String message) {
        callbacks.printError(message);
    }

    /*
     * The code below is based on
     * https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm#Java
     */

    /**
     * Load a {@link PrivateKey} from a file.
     */
    private static PrivateKey loadPrivateKey(String privateKeyFilename) {
        try (InputStream privateKeyStream = Files.newInputStream(Paths.get(privateKeyFilename))) {
            return PEM.readPrivateKey(privateKeyStream);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Invalid format for private key");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load private key");
        }
    }

    /**
     * A light wrapper around https://github.com/tomitribe/http-signatures-java
     */
    public static class RequestSigner {
        private static final SimpleDateFormat DATE_FORMAT;
        private static final String SIGNATURE_ALGORITHM = "rsa-sha256";
        private Map<String, List<String>> REQUIRED_HEADERS;

        static {
            DATE_FORMAT = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
        }

        private final Map<String, Signer> signers;

        /**
         * @param apiKey     The identifier for a key uploaded through the console.
         * @param privateKey The private key that matches the uploaded public key for the given apiKey.
         */
        public RequestSigner(String apiKey, Key privateKey) {
            REQUIRED_HEADERS = new HashMap<String, List<String>>();
            REQUIRED_HEADERS.put("get", stringToList(globalSettings.getString("Header Names to Sign: GET").toLowerCase()));
            REQUIRED_HEADERS.put("head", stringToList(globalSettings.getString("Header Names to Sign: HEAD").toLowerCase()));
            REQUIRED_HEADERS.put("delete", stringToList(globalSettings.getString("Header Names to Sign: DELETE").toLowerCase()));
            REQUIRED_HEADERS.put("put", stringToList(globalSettings.getString("Header Names to Sign: PUT").toLowerCase()));
            REQUIRED_HEADERS.put("post", stringToList(globalSettings.getString("Header Names to Sign: POST").toLowerCase()));

            this.signers = REQUIRED_HEADERS
                    .entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> entry.getKey(),
                            entry -> buildSigner(apiKey, privateKey, entry.getKey())));
        }

        /**
         * Create a List from a string using the default StringTokenizer delimiter set (" \t\n\r\f")
         * @param input_string   The string to convert to a List
         * @return               The converted string in a List format
         */
        private List stringToList(String input_string) {
            List<String> list = new ArrayList<String>();
            StringTokenizer st = new StringTokenizer(input_string);
            while (st.hasMoreTokens()) {
                list.add(st.nextToken());
            }
            return list;
        }

        /**
         * Create a {@link Signer} that expects the headers for a given method.
         *
         * @param apiKey     The identifier for a key uploaded through the console.
         * @param privateKey The private key that matches the uploaded public key for the given apiKey.
         * @param method     HTTP verb for this signer
         * @return           Signer
         */
        protected Signer buildSigner(String apiKey, Key privateKey, String method) {
            final Signature signature = new Signature(
                    apiKey, SIGNATURE_ALGORITHM, null, REQUIRED_HEADERS.get(method.toLowerCase()));
            return new Signer(privateKey, signature);
        }

        /**
         * Sign a request, optionally including additional headers in the signature.
         *
         * <ol>
         * <li>If missing, insert the Date header (RFC 2822).</li>
         * <li>If PUT or POST, insert any missing content-type, content-length, x-content-sha256/digest</li>
         * <li>Verify that all headers to be signed are present.</li>
         * <li>Set the request's Authorization header to the computed signature.</li>
         * </ol>
         *
         * @param request The request to sign
         * @param header_name The header name for the signature
         */
        public void signRequest(HttpRequestBase request, String header_name) {
            final String method = request.getMethod().toLowerCase();
            // nothing to sign for options
            if (method.equals("options")) {
                return;
            }

            boolean includeQuery = true;
            // Some implementations require query parameters in the Signatures, some don't.
            // If "Include query parameters in Signature" is set to "true", include query parameters in the Signature,
            // if set to "false" don't include query parameters in the Signature.
            if (globalSettings.getString("Include query parameters in Signature").equalsIgnoreCase("false")) {
                includeQuery = false;
            }
            final String path = extractPath(request.getURI(), includeQuery);

            // supply date if missing
            if (!request.containsHeader("date")) {
                request.addHeader("date", DATE_FORMAT.format(new Date()));
            }

            // supply host if missing
            if (!request.containsHeader("host")) {
                request.addHeader("host", request.getURI().getHost());
            }

            // supply content-type, content-length, and x-content-sha256/digest if missing (PUT and POST requests only)
            if (method.equals("put") || method.equals("post")) {
                if (!request.containsHeader("content-type")) {
                    request.addHeader("content-type", "application/json");
                }
                byte[] body = getRequestBody((HttpEntityEnclosingRequestBase) request);

                if (!request.containsHeader("content-length") ||
                        !request.containsHeader(globalSettings.getString("Digest Header Name").toLowerCase())) {
                    
                    if (!request.containsHeader("content-length")) {
                        request.addHeader("content-length", Integer.toString(body.length));
                    }
                }

                // always recalculate the digest for POST/PUT requests
                if (globalSettings.getString("Digest Header Name").toLowerCase().equals("x-content-sha256") ) {
                    request.setHeader("x-content-sha256", calculateSHA256(body));
                } else {
                    request.setHeader("digest", "SHA-256="+calculateSHA256(body));
                }

            }

            final Map<String, String> headers = extractHeadersToSign(request);
            String signature = this.calculateSignature(method, path, headers);
            //log("DEBUG: signed signature: " + signature);

            if (header_name.equalsIgnoreCase("Signature") && signature.startsWith("Signature ")) {
                // remove "Signature" from the beginning of the string as we use "Signature" as the header name
                signature = signature.substring(10);
            }
            request.setHeader(header_name, signature);
        }

        /**
         * Extract path and query string to build the (request-target) pseudo-header.
         * For the URI "http://www.host.com/somePath?foo=bar" return "/somePath?foo=bar"
         *
         * @param uri The URI to extract the path
         * @param includeQuery If true include the query parameters (e.g. "?foo=bar"), if false do not include query params
         */
        private static String extractPath(URI uri, boolean includeQuery) {
            String path = uri.getRawPath();
            String query = uri.getRawQuery();
            if (query != null && !query.trim().isEmpty() && includeQuery) {
                path = path + "?" + query;
            }
            return path;
        }

        /**
         * Extract the headers required for signing from a {@link HttpRequestBase}, into a Map
         * that can be passed to {@link RequestSigner#calculateSignature}.
         *
         * <p>
         * Throws if a required header is missing, or if there are multiple values for a single header.
         * </p>
         *
         * @param request The request to extract headers from.
         */
        private Map<String, String> extractHeadersToSign(HttpRequestBase request) {
            List<String> headersToSign = REQUIRED_HEADERS.get(request.getMethod().toLowerCase());
            if (headersToSign == null) {
                throw new RuntimeException("Don't know how to sign method " + request.getMethod());
            }
            return headersToSign.stream()
                    // (request-target) is a pseudo-header
                    .filter(header -> !header.toLowerCase().equals("(request-target)"))
                    .collect(Collectors.toMap(
                            header -> header,
                            header -> {
                                if (!request.containsHeader(header)) {
                                    throw new MissingRequiredHeaderException(header);
                                }
                                if (request.getHeaders(header).length > 1) {
                                    throw new RuntimeException(
                                            String.format("Expected one value for header %s", header));
                                }

                                // If the configuration setting "Include the port in Signature" is set to false, remove the port.
                                // Some implementations such as Nextcloud Social do not include the port in the signature
                                // calculation.
                                if (header.equalsIgnoreCase("host") &&
                                        (request.getFirstHeader(header).getValue().indexOf(':') > -1 ) &&
                                        globalSettings.getString("Include the port in Signature").equalsIgnoreCase("false")) {
                                    // remove the port after the hostname, e.g. localhost:8080 -> localhost
                                    return request.getFirstHeader(header).getValue().split(":")[0];
                                } else {
                                    return request.getFirstHeader(header).getValue();
                                }
                            }));
        }

        /**
         * Wrapper around {@link Signer # sign}, returns the {@link Signature} as a String.
         *
         * @param method  Request method (GET, POST, ...)
         * @param path    The path + query string for forming the (request-target) pseudo-header
         * @param headers Headers to include in the signature.
         */
        private String calculateSignature(String method, String path, Map<String, String> headers) {
            Signer signer = this.signers.get(method);
            if (signer == null) {
                throw new RuntimeException("Don't know how to sign method " + method);
            }
            try {
                return signer.sign(method, path, headers).toString();
            } catch (IOException e) {
                throw new RuntimeException("Failed to generate signature", e);
            }
        }

        /**
         * Calculate the Base64-encoded string representing the SHA256 of a request body
         *
         * @param body The request body to hash
         * @return     The Base64-encoded SHA256 hash (empty string if NoSuchAlgorithmException)
         */
        private String calculateSHA256(byte[] body) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(body);
                return Base64.getEncoder().encodeToString(hash);
            } catch (NoSuchAlgorithmException e) {
                err("Unable to create SHA256 (NoSuchAlgorithmException)");
                return "";
            }
        }

        /**
         * Helper to safely extract a request body.  Because an {@link HttpEntity} may not be repeatable,
         * this function ensures the entity is reset after reading.  Null entities are treated as an empty string.
         *
         * @param request A request with a (possibly null) {@link HttpEntity}
         */
        private byte[] getRequestBody(HttpEntityEnclosingRequestBase request) {
            HttpEntity entity = request.getEntity();
            // null body is equivalent to an empty string
            if (entity == null) {
                return "".getBytes(StandardCharsets.UTF_8);
            }
            // May need to replace the request entity after consuming
            boolean consumed = !entity.isRepeatable();
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            try {
                entity.writeTo(content);
            } catch (IOException e) {
                throw new RuntimeException("Failed to copy request body", e);
            }
            // Replace the now-consumed body with a copy of the content stream
            byte[] body = content.toByteArray();
            if (consumed) {
                request.setEntity(new ByteArrayEntity(body));
            }
            return body;
        }
    }
}
