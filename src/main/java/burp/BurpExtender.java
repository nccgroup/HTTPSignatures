package burp;

import javax.swing.*;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IExtensionHelpers helpers;

    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks) {
        new Signing(callbacks);
        callbacks.setExtensionName("Signing HTTP Messages");
        this.helpers = callbacks.getHelpers();
        SwingUtilities.invokeLater(new ConfigMenu());

        // register ourselves as an HTTP listener (any burp tool)
        callbacks.registerHttpListener(BurpExtender.this);
        
        // Set the debug flag from the settings
        if ( Signing.callbacks.loadExtensionSetting("debug") != null &&
                Signing.callbacks.loadExtensionSetting("debug").equals("true") ) {
            Signing.DEBUG = true;
        }
    }

    /**
     * This method is invoked when an HTTP request is about to be issued, and
     * when an HTTP response has been received.
     *
     * @param toolFlag A flag indicating the Burp tool that issued the request.
     * Burp tool flags are defined in the
     * <code>IBurpExtenderCallbacks</code> interface.
     * @param messageIsRequest Flags whether the method is being invoked for a
     * request or response.
     * @param messageInfo Details of the request / response to be processed.
     * Extensions can call the setter methods on this object to update the
     * current message and so modify Burp's behavior.
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        // Process only requests (and not responses)
        if (!messageIsRequest) {
            return;
        }

        // Check if this extension is enabled for the current Burp tool request
        if (Signing.enabledForTool(toolFlag)) {

            // if there is no active key, do not sign this request
            if (Signing.callbacks.loadExtensionSetting("ActiveKey") == null) {
                return;
            }

            IRequestInfo request = helpers.analyzeRequest(messageInfo.getRequest());
            java.util.List<String> headers = request.getHeaders();
            String profileValues = Signing.callbacks.loadExtensionSetting("ActiveKey");
            // get the header value (first element) from profileValues
            String[] valuesParts = profileValues.split(";");
            String header = valuesParts[0].toLowerCase();

            // Process only requests containing an HTTP header starting with the configured header name (e.g. Authorization, Signature)
            if (headers.stream().anyMatch((str -> str.trim().toLowerCase().contains(header)))) {
                messageInfo.setRequest(Signing.signRequest(messageInfo));
            }
        }
    }
}
