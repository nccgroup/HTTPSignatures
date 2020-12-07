# `HTTPSignatures` Burp Suite Extension

`HTTPSignatures` is a Burp Suite extension that implements the Signing HTTP Messages [`draft-ietf-httpbis-message-signatures-01`](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-01) specification draft document.
This allows Burp Suite users to seamlessly test applications that require HTTP Signatures.


## Features

- Automatically creates a new signature and digest in Burp Repeater, Intruder, and Scanner when the extension detects an existing HTTP Signature header. 
- Supports the `rsa-sha256` algorithm for signing messages (`RSASSA-PKCS1-v1_5` [[RFC8017](https://tools.ietf.org/html/rfc8017)] using SHA-256 [[RFC6234](https://tools.ietf.org/html/rfc6234)]) and SHA-256 for the digest header. 
- The extension works in Burp Suite Professional and in the free Burp Suite Community Edition.

## Usage

### Installation

Download the [latest JAR release](https://github.com/nccgroup/HTTPSignatures/releases/latest) file and add it in Burp Suite through Extender Tab / Extensions / Add.

### Configuration

1. After loading the extension a new *HTTP Signatures* menu item will be added to Burp.
2. Open the configuration tab (click the *HTTP Signatures* menu item).
3. The minimum configuration requires the `Header Name`, the ``keyId``, and the `Private key file name and path` to be configured. See below for the detailed description. 
4. You can now use Burp Proxy, Repeater, Intruder, and Scanner. 
   The extension will create a new Signature for each request that contains the configured `Header Name`.

### Use

After `HTTPSignatures` has been correctly configured, the Burp Suite extension will replace the HTTP header value configured in the `Header Name` setting (e.g. `Signature`) with a new signature for every HTTP request sent through Burp Proxy, Repeater, Intruder, and Scanner.

![`HTTPSignatures` Configuration](screenshots/config.png)

## Documentation

The Burp Suite extension must be configured before it can be used. 
The `HTTPSignatures` configuration can be found in the Burp menu after it has been loaded (usually on the right of the Help menu). 
The `Header Name`, the `keyId`, and the `Private key file name and path` have to be correctly configured for the extension to work.
The remaining settings can optionally be adjusted.

- **Header Name**: (sample values: `Authorization`, `Signature`): The name of the HTTP request header that includes the signature. 
The IETF draft is using the `Signature` header name. Oracle Cloud (OCI) is using the `Authorization` header name.

- **keyId**: The `keyId` parameter is a US-ASCII string used by a verifier to identify and/or obtain the signature's verification key.
Sample values can look like `https://mastodon.example.com/users/myUser` (for ActivityPub) or `ocid1.tenancy.oc1.../ocid1.user.oc1.../{fingerprint}` for OCI.

- **Private key file name and path**: The full path and file name containing the private key (e.g. `/home/${USER}/private_key.pem`).
- **Digest Header Name**: The name of the header containing the digest. This should be either `x-content-sha256` (for OCI) or `digest` for most other implementations.
- **Header Names to Sign: GET**: The header names to include for GET requests (e.g. `date (request-target) host`).
The `(request-target)` value is a special identifier consisting of the request method and the path and query of the request URI (e.g. `get /foo?param=value`).
- **Header Names to Sign: HEAD**: The header names to include in HEAD requests (e.g. `date (request-target) host`).
- **Header Names to Sign: DELETE**: The header names to include in DELETE requests (e.g. `date (request-target) host`).
- **Header Names to Sign: PUT**: The header names to include in PUT requests (e.g. `date (request-target) host content-length content-type digest`).
- **Header Names to Sign: POST**: The header names to inlcude in POST requets (e.g. `date (request-target) host content-length content-type digest`).
- **Include query parameters in Signature**: This boolean value specifies if query parameters (e.g. `?param=value`) should be included in the signature. 
While the draft standard specifies that query parameters are part of the `(request-target)` identifier, not all implementations include query parameters. 
The default value is `true`.
- **Include the port in Signature**: Some implementations do not include the port in the host header (e.g. `localhost:8080`). 
This setting allows to remove the port from the host header value if set to `false`. 
The default value is `true`.

### Profiles

The `HTTPSignatures` configuration allows to configure multiple profiles in tabs. 
Create a new tab by clicking on the `...` tab. 
You can name tabs by double clicking on a tab. 
To save a tab click the "Save" button. 
To mark a tab as the active profile, click the "Use this profile" button.
The **active tab** (profile) is marked with red font and border.

### Global Configuration Settings

The global configuration section contains settings that apply to all profiles.

- **Enable the extension for the following Burp Suite tools**: The extension can be enabled or disabled for the following Burp Suite tools:
    - Proxy (default: disabled)
    - Scanner (default: enabled)
    - Intruder (default: enabled)
    - Repeater (default: enabled)

    The proxy is disabled be default. The oder tools are enabled by default. The proxy tool should usually only be enabled when using the intercept feature. The extension will not update the signature when it is disabled.

- **Enable Debug Logs**: Enabling this checkbox will print debug logs to the standard output. 
  The output can be configured in Burp Suite under Extender -> Extensions, then select the *Signing HTTP Messages* extension. 
  In the *Output* tab you can select where the standard output will be shown. 
  The default is *Shown in UI* where the output will be displayed within Burp Suite. 

## Example Configurations

### ActivityPub

[ActivityPub](https://www.w3.org/TR/activitypub/) uses HTTP Signatures for [server to server authentication and authorization](https://www.w3.org/wiki/SocialCG/ActivityPub/Authentication_Authorization). 

- Header Name: `Signature`
- keyId: The keyId should link to the actor so that the publicKey field can be retrieved: `https://mastodon.online/users/viktor`. 
  You can use `curl` to retrieve the key: `curl https://mastodon.online/users/viktor -H 'Accept: application/activity+json'|jq`
- Private key file name and path: `/home/user/private_key.pem`
- Digest Header Name: `digest`
- Header Names to Sign: GET: `date (request-target) host`
- Header Names to Sign: HEAD: `date (request-target) host`
- Header Names to Sign: DELETE: `date (request-target) host`
- Header Names to Sign: PUT: `date (request-target) host content-length content-type digest`
- Header Names to Sign: POST: `date (request-target) host content-length content-type digest`
- Include query parameters in Signature: `true`
- Include the port in Signature: `true`

### Oracle Cloud Infrastructure (OCI)

All Oracle Cloud Infrastructure (OCI) API requests [require HTTP Signatures](https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm). 
The implementation is based on the draft specification with some modifications.

- Header Name: `Authorization`
- keyId: `<TENANCY OCID>/<USER OCID>/<KEY FINGERPRINT>`, e.g. `ocid1.tenancy.oc1..<unique_ID>/ocid1.user.oc1..<unique_ID>/<key_fingerprint>`
- Private key file name and path: `/home/user/private_key.pem`
- Digest Header Name: `x-content-sha256`
- Header Names to Sign: GET: `date (request-target) host`
- Header Names to Sign: HEAD: `date (request-target) host`
- eader Names to Sign: DELETE: `date (request-target) host`
- Header Names to Sign: PUT: `date (request-target) host content-length content-type x-content-sha256`
- Header Names to Sign: POST: `date (request-target) host content-length content-type x-content-sha256`
- Include query parameters in Signature: `true`
- Include the port in Signature: `true`


## Building with IntelliJ IDEA

1. Clone this repository and *Open or Import* the `HTTPSignatures` folder in IntelliJ IDEA.
2. Compile the project (Build -> Build Project)
3. Create a JAR file to import in Burp Suite: Go to File -> Project Structure, select Project Settings -> Artifacts.
4. Click the plus sign to create a new JAR file "From modules with dependencies" and click OK.
5. Select the "Include in project build" checkbox to automatically create a JAR file when building the project and click OK.
6. Build the project again (Ctrl+F9 or ⌘+F9).
7. The JAR file is created in the project folder at `out/artifacts/HTTPSignatures_jar/HTTPSignatures.jar`.
8. Load the JAR file in Burp through the Extender Tab -> Extensions -> Add.

## Building on the Command Line using Maven

1. Clone this repository.
2. Compile the project and create a JAR file with the command `mvn package assembly:single`. 
3. The JAR file is created in the project folder at `target/HTTPSignatures-1.0-SNAPSHOT-jar-with-dependencies.jar`.
4. Load the JAR file in Burp through the Extender Tab -> Extensions -> Add.

### Dependencies

Three dependencies are required to build the Java project:
- Apache HttpClient (https://hc.apache.org/httpcomponents-client-ga/)
- Tomitribe's HTTP Signatures Java Client (https://github.com/tomitribe/http-signatures-java)
- Burp Extender API (https://github.com/PortSwigger/burp-extender-api)


