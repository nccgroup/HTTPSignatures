package burp;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;

import static burp.Signing.log;

public class ConfigSettings {
    public LinkedHashMap<String, String> settings; // key is e.g. "Header", value is "Authorization"
    // profiles: key is the name of the Tab, value is a settings LinkedHashMap
    private LinkedHashMap<String, LinkedHashMap<String, String>> profiles;
    private JPanel rootPanel; // The root panel where every UI component is drawn
    public JTabbedPane tabbedPane; // The tabs to configure the profiles in the UI
    JCheckBox checkBoxDebug = new JCheckBox("Enable Debug Logs");
    JCheckBox checkBoxToolProxy = new JCheckBox("Proxy");
    JCheckBox checkBoxToolScanner = new JCheckBox("Scanner");
    JCheckBox checkBoxToolIntruder = new JCheckBox("Intruder");
    JCheckBox checkBoxToolRepeater = new JCheckBox("Repeater");
    private boolean tabChangeListenerLock = false;

    ConfigSettings() {
        settings = new LinkedHashMap<>();
        settings.put("Header Name", "e.g. Authorization, Signature");
        settings.put("keyId", "e.g. https://example.com/user1, ocid1.tenancy.oc1.../ocid1.user.oc1.../{fingerprint}");
        settings.put("Private key file name and path", "/home/${USER}/private_key.pem");
        settings.put("Digest Header Name", "e.g. x-content-sha256 or digest");
        settings.put("Header Names to Sign: GET", "date (request-target) host");
        settings.put("Header Names to Sign: HEAD", "date (request-target) host");
        settings.put("Header Names to Sign: DELETE", "date (request-target) host");
        settings.put("Header Names to Sign: PUT", "date (request-target) host content-length content-type digest");
        settings.put("Header Names to Sign: POST", "date (request-target) host content-length content-type digest");
        settings.put("Include query parameters in Signature", "true");
        settings.put("Include the port in Signature", "true");

        profiles = new LinkedHashMap<>();

        //Signing.callbacks.saveExtensionSetting("<tabNames>", null); // purge saved settings

        String tabNames = Signing.callbacks.loadExtensionSetting("<tabNames>");
        if (tabNames == null) {
            log("no saved tabs");
            // if <tabNames> is empty, then we don't have any saved tabs
            profiles.put("ActiveKey", settings); // the first element is the currently active key
        } else {
            // load stored settings
            String activeTabName = Signing.callbacks.loadExtensionSetting("<ActiveTabName>");
            if (activeTabName == null) {
                activeTabName = "";
            }
            String[] tabNameParts = tabNames.split(";");
            for (int tabNum = 0; tabNum < tabNameParts.length; tabNum++) {
                String tabName = tabNameParts[tabNum];
                log("putting tab " + tabName + " in profiles");
                String values = Signing.callbacks.loadExtensionSetting(tabName);
                if (values != null) {
                    LinkedHashMap<String, String> newProfile = new LinkedHashMap<>();
                    String[] valuesParts = values.split(";");
                    int i = 0;
                    for (String key : settings.keySet()) {
                        String valuesPartsStr = "";
                        if (i < valuesParts.length) {
                            valuesPartsStr = valuesParts[i++];
                        }
                        log("loading key: " + key + " value: " + valuesPartsStr);
                        newProfile.put(key, valuesPartsStr);
                    }
                    profiles.put(tabName, newProfile);
                    // update the profiles LinkedHashMap with the active key
                    if (activeTabName.equals(tabName)) {
                        profiles.put("ActiveKey", newProfile);
                    }
                }
            }
        }
    }

    /**
     * Return the Burp frame used for the option dialog and the menu button
     * @return  The Burp Suite frame
     */
    static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    /**
     * Get the value from a key/profile setting (e.g. "keyId") from the active profile
     * @param key   The key to retrieve
     * @return      The value for the key belonging to the active profile
     */
    public String getString(String key) {
        return profiles.get("ActiveKey").get(key);
    }

    /**
     * Display the configuration window
     */
    protected void showSettings() {
        rootPanel = new JPanel();
        rootPanel.setLayout(new BorderLayout());
        tabbedPane = new JTabbedPane();

        JPanel globalPanel = new JPanel(); // The global panel contains the global settings above the profile tabs
        globalPanel.setLayout(new BoxLayout(globalPanel, BoxLayout.PAGE_AXIS));
        JLabel titleGlobalConfig = new JLabel("Global Configuration Settings");
        titleGlobalConfig.setForeground(Color.ORANGE);
        titleGlobalConfig.setFont(titleGlobalConfig.getFont().deriveFont(Font.BOLD, titleGlobalConfig.getFont().getSize() + 4));
        globalPanel.add(titleGlobalConfig);
        // Checkboxes to enable/disable the extension for each Burp Suite tool
        JLabel labelTools = new JLabel("Enable the extension for the following Burp Suite tools:");
        Font labelToolsFont = labelTools.getFont();
        labelTools.setFont(labelToolsFont.deriveFont(labelToolsFont.getStyle() | Font.BOLD)); // make text bold
        globalPanel.add(labelTools);
        if ((Signing.callbacks.loadExtensionSetting("enableProxy") != null) &&
                Signing.callbacks.loadExtensionSetting("enableProxy").equals("true")) {
            checkBoxToolProxy.setSelected(true);
        } else {
            checkBoxToolProxy.setSelected(false);
        }
        globalPanel.add(checkBoxToolProxy);
        if ((Signing.callbacks.loadExtensionSetting("enableScanner") != null) &&
                Signing.callbacks.loadExtensionSetting("enableScanner").equals("true")) {
            checkBoxToolScanner.setSelected(true);
        } else {
            checkBoxToolScanner.setSelected(false);
        }
        globalPanel.add(checkBoxToolScanner);
        if ((Signing.callbacks.loadExtensionSetting("enableIntruder") != null) &&
                Signing.callbacks.loadExtensionSetting("enableIntruder").equals("true")) {
            checkBoxToolIntruder.setSelected(true);
        } else {
            checkBoxToolIntruder.setSelected(false);
        }
        globalPanel.add(checkBoxToolIntruder);
        if ((Signing.callbacks.loadExtensionSetting("enableRepeater") != null) &&
                Signing.callbacks.loadExtensionSetting("enableRepeater").equals("true")) {
            checkBoxToolRepeater.setSelected(true);
        } else {
            checkBoxToolRepeater.setSelected(false);
        }
        globalPanel.add(checkBoxToolRepeater);
        // Debugging settings
        JLabel labelDebugging = new JLabel("Debugging");
        Font labelDebuggingFont = labelDebugging.getFont();
        labelDebugging.setFont(labelDebuggingFont.deriveFont(labelDebuggingFont.getStyle() | Font.BOLD)); // make text bold
        globalPanel.add(labelDebugging);
        checkBoxDebug.setSelected(Signing.DEBUG); // set the checkbox if debugging logs is enabled
        globalPanel.add(checkBoxDebug);
        Dimension minSize = new Dimension(0, 10);
        Dimension prefSize = new Dimension(0, 10);
        Dimension maxSize = new Dimension(Short.MAX_VALUE, 10);
        globalPanel.add(new Box.Filler(minSize, prefSize, maxSize));

        // Link to documentation
        String doc = new String("Documentation: https://github.com/nccgroup/HTTPSignatures");
        JLabel labelDoc = new JLabel(doc);
        labelDoc.setForeground(Color.BLUE.darker());
        labelDoc.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        labelDoc.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // the user clicks on the label
                try {
                    Desktop.getDesktop().browse(new URI("https://github.com/nccgroup/HTTPSignatures"));
                } catch (IOException | URISyntaxException e1) {}
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                // the mouse has entered the label
                Font labelDocFont = labelDebugging.getFont();
                labelDoc.setFont(labelDocFont.deriveFont(labelDocFont.getStyle() | Font.BOLD)); // make text bold
            }

            @Override
            public void mouseExited(MouseEvent e) {
                // the mouse has exited the label
                labelDoc.setText(doc);
            }
        });
        globalPanel.add(labelDoc);

        globalPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
        minSize = new Dimension(0, 10);
        prefSize = new Dimension(0, 25);
        maxSize = new Dimension(Short.MAX_VALUE, 25);
        globalPanel.add(new Box.Filler(minSize, prefSize, maxSize));
        JLabel titleProfileConfig = new JLabel("Profile Configuration");
        titleProfileConfig.setForeground(Color.ORANGE);
        titleProfileConfig.setFont(titleProfileConfig.getFont().deriveFont(Font.BOLD, titleProfileConfig.getFont().getSize() + 4));
        globalPanel.add(titleProfileConfig);

        rootPanel.add(globalPanel, BorderLayout.PAGE_START);

        initTabs();

        // Add "new tab" tab
        JPanel newTabButton = new JPanel();
        newTabButton.setName("...");
        tabbedPane.add(newTabButton);

        tabbedPane.addChangeListener((ChangeEvent e) -> {
            // If the '...' button is pressed, add a new tab
            if (!tabChangeListenerLock) {
                if (tabbedPane.getSelectedIndex() == tabbedPane.getTabCount() - 1) {
                    log("addTab() ... button");
                    addTab();
                }
            }
        });

        rootPanel.add(tabbedPane);

        Object[] options = {"Use this profile",
                "Cancel",
                "Save"};
        int result = JOptionPane.showOptionDialog(
                ConfigSettings.getBurpFrame(),
                rootPanel,
                "HTTP Signatures Configuration",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[2]);

        if (result == JOptionPane.YES_OPTION) { // "Use this profile" button
            // Set this (selected) profile active
            setActiveProfile((ProfileTab) tabbedPane.getSelectedComponent());

        } else if (result == JOptionPane.CANCEL_OPTION) { // "Save" button
            // Save all tabs (profiles)
            saveProfiles();

        } // else if (result == JOptionPane.NO_OPTION) {} // "Cancel" button
    }

    /**
     * Make a ProfileTab active
     * @param profileTab   The ProfileTab to set active
     */
    private void setActiveProfile(ProfileTab profileTab) {
        String tabName = profileTab.profileTabHandle.tabNameField.getText();
        tabName.replaceAll(";",""); // remove semicolons
        log("Setting active profile to '" + tabName + "' active");

        LinkedHashMap<String, Object> newProfile = profileTab.getNewProfile();
        LinkedHashMap<String, String> newProfile2 = new LinkedHashMap<>();
        String profileValues = "";
        for (String key : newProfile.keySet()) {
            if (!profileValues.isEmpty()) {
                // add semicolon; but not on first key
                profileValues = profileValues + ";";
            }
            Object val = newProfile.get(key);
            String valStr = ((JTextField) val).getText();
            profileValues += valStr.replaceAll(";",""); // remove semicolons
            newProfile2.put(key, valStr);
            log("Setting active profile " + tabName + ": key: " + key + " value: " + valStr);
        }
        newProfile2.put("<ActiveTabName>", tabName);
        log("Active profile values: " + profileValues);
        profiles.put("ActiveKey", newProfile2);
        Signing.callbacks.saveExtensionSetting("ActiveKey", profileValues);
        Signing.callbacks.saveExtensionSetting("<ActiveTabName>", tabName);
    }

    /**
     * Save all tabs
     */
    private void saveProfiles() {
        int totalTabs = tabbedPane.getTabCount();
        String tabNames = "";
        log("Saving " + totalTabs + " tabs");
        // load active tab name
        String activeTabName = Signing.callbacks.loadExtensionSetting("<ActiveTabName>");
        if (activeTabName == null) {
            activeTabName = "";
        }
        for (int tabNum = 0; tabNum < totalTabs; tabNum++) {

            ProfileTab.ProfileTabHandle profileTabHandle = (ProfileTab.ProfileTabHandle) tabbedPane.getTabComponentAt(tabNum);
            ProfileTab profileTab;
            try {
                profileTab = profileTabHandle.profileTab;
            } catch (NullPointerException e) {
                continue;
            }
            LinkedHashMap<String, Object> newProfile = profileTab.getNewProfile();
            String tabName = profileTab.profileTabHandle.tabNameField.getText();
            tabName = tabName.replaceAll(";",""); // remove semicolons

            if (!tabNames.isEmpty()) {
                // add semicolon, but not on first key
                tabNames = tabNames + ";";
            }
            tabNames += tabName;

            log("Saving tab " + tabName);
            String profileValues = "";
            for (String key : newProfile.keySet()) {
                if (!profileValues.isEmpty()) {
                    // add semicolon; but not on first key
                    profileValues = profileValues + ";";
                }
                Object val = newProfile.get(key);
                String valStr = ((JTextField) val).getText();
                valStr = valStr.replaceAll(";",""); // remove any semicolon
                profileValues += valStr;
                log("Saving profile " + tabName + ": key: " + key + " value: " + valStr);
            }
            log("SAVING: " + tabName + ": profileValues: " + profileValues);
            Signing.callbacks.saveExtensionSetting(tabName, profileValues);

            // if this is the currently active tab, then update the settings for the active tab also
            if (activeTabName.equals(tabName)) {
                setActiveProfile(profileTab);
            }
        }
        log("tabNames: " + tabNames);
        Signing.callbacks.saveExtensionSetting("<tabNames>", tabNames);

        // save global settings
        if (checkBoxToolProxy.isSelected()) {
            Signing.callbacks.saveExtensionSetting("enableProxy", "true");
        } else {
            Signing.callbacks.saveExtensionSetting("enableProxy", "false");
        }
        if (checkBoxToolScanner.isSelected()) {
            Signing.callbacks.saveExtensionSetting("enableScanner", "true");
        } else {
            Signing.callbacks.saveExtensionSetting("enableIntruder", "false");
        }
        if (checkBoxToolIntruder.isSelected()) {
            Signing.callbacks.saveExtensionSetting("enableIntruder", "true");
        } else {
            Signing.callbacks.saveExtensionSetting("enableIntruder", "false");
        }
        if (checkBoxToolRepeater.isSelected()) {
            Signing.callbacks.saveExtensionSetting("enableRepeater", "true");
        } else {
            Signing.callbacks.saveExtensionSetting("enableRepeater", "false");
        }
        if (checkBoxDebug.isSelected()) {
            Signing.DEBUG = true;
            Signing.callbacks.saveExtensionSetting("debug", "true");
        } else {
            Signing.DEBUG = false;
            Signing.callbacks.saveExtensionSetting("debug", "false");
        }
    }

    /**
     * Add an unnamed tab
     */
    private void addTab() {
        int totalTabs = tabbedPane.getTabCount();
        if (totalTabs < 1) {
            totalTabs = 1; // When there are no tabs (first run), there will be 0 tabs
        }
        addTab(String.valueOf(totalTabs));
    }

    /**
     * Add a new (empty) tab
     * @param tabName   the name of the new tab
     */
    private void addTab(String tabName) {
        tabChangeListenerLock = true;
        ProfileTab newProfileTab = new ProfileTab(tabName, this, "");
        tabbedPane.add(newProfileTab, tabbedPane.getTabCount() - 1);
        tabbedPane.setTabComponentAt(tabbedPane.indexOfComponent(newProfileTab), newProfileTab.getTabHandleElement());
        tabbedPane.setSelectedComponent(newProfileTab);
        tabChangeListenerLock = false;
    }

    /**
     * Add a new tab with content
     * @param tabName    The name of the new tab
     * @param tabConfig  The configuration of the new tab (values separated by semicolons)
     * @param active     Boolean: true means the profile is active; false means the profile is not active
     */
    private void addTab(String tabName, String tabConfig, Boolean active) {
        tabChangeListenerLock = true;
        ProfileTab newProfileTab = new ProfileTab(tabName, this, tabConfig);
        tabbedPane.add(newProfileTab, tabbedPane.getTabCount());
        tabbedPane.setTabComponentAt(tabbedPane.indexOfComponent(newProfileTab), newProfileTab.getTabHandleElement());
        tabbedPane.setSelectedComponent(newProfileTab);
        if (active) {
            newProfileTab.profileTabHandle.tabNameField.setFont(
                    newProfileTab.profileTabHandle.tabNameField.getFont().deriveFont(Font.BOLD));
            newProfileTab.profileTabHandle.tabNameField.setForeground(Color.RED);
            newProfileTab.setBorder(BorderFactory.createLineBorder(Color.RED));
            newProfileTab.setOpaque(true);
            // Set the background of the active tab to a different color
            // depending on the brightness of the theme.
            if (isColorBright(newProfileTab.getBackground().getRGB())) {
                newProfileTab.setBackground(Color.ORANGE);
            } else {
                newProfileTab.setBackground(new Color(153, 102, 0));
            }
        }
        tabChangeListenerLock = false;
    }

    /**
     * Checks if a color is bright or dark.
     * @param color   The RGB color
     * @return        True if bright, false if dark
     */
    private boolean isColorBright(int color) {
        if (brightness(color) > 0.5) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns the brightness of a color.
     * Based on
     * https://chromium.googlesource.com/android_tools/+/18728e9dd5dd66d4f5edf1b792e77e2b544a1cb0/sdk/sources/android-19/android/graphics/Color.java#187
     * @param color  The RGB color
     * @return       A value between 0.0f and 1.0f
     */
    private float brightness(int color) {
        int r = (color >> 16) & 0xFF;
        int g = (color >> 8) & 0xFF;
        int b = color & 0xFF;
        int V = Math.max(b, Math.max(r, g));

        return (V / 255.f);
    }

    /**
     * Close a tab
     * @param configTabContent   The tab to close
     */
    public void closeTab(JPanel configTabContent) {
        tabChangeListenerLock = true;
        if (tabbedPane.getSelectedComponent().equals(configTabContent)) {
            if (tabbedPane.getTabCount() == 2) {
                tabbedPane.remove(configTabContent);
                addTab();
                tabChangeListenerLock = true;
            } else if (tabbedPane.getTabCount() > 2) {
                tabbedPane.remove(configTabContent);
            }
            if (tabbedPane.getSelectedIndex() == tabbedPane.getTabCount() - 1) {
                tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 2);
            }
        } else {
            tabbedPane.setSelectedComponent(configTabContent);
        }
        tabChangeListenerLock = false;
    }

    /**
     * Initialize the tabs with the saved settings
     */
    private void initTabs() {

        String tabNames = Signing.callbacks.loadExtensionSetting("<tabNames>");
        if (tabNames == null) {
            log("initTabs(): no saved tabs");
            addTab();
        } else {
            // load stored settings
            String activeTabName = Signing.callbacks.loadExtensionSetting("<ActiveTabName>");
            if (activeTabName == null) {
                activeTabName = "";
            }
            String[] tabNameParts = tabNames.split(";");
            for (int tabNum = 0; tabNum < tabNameParts.length; tabNum++) {
                String tabName = tabNameParts[tabNum];
                String values = Signing.callbacks.loadExtensionSetting(tabName);
                log("displaying tab '" + tabName + "' VALUES: " + values);
                if (values != null) {
                    if (activeTabName.equals(tabName)) {
                        addTab(tabName, values, true);
                    } else {
                        addTab(tabName, values, false);
                    }
                }
            }
            // Focus the active profile tab
            int totalTabs = tabbedPane.getTabCount();
            for (int tabNum = 0; tabNum < totalTabs; tabNum++) {
                ProfileTab.ProfileTabHandle profileTabHandle = (ProfileTab.ProfileTabHandle) tabbedPane.getTabComponentAt(tabNum);
                ProfileTab profileTab;
                try {
                    profileTab = profileTabHandle.profileTab;
                } catch (NullPointerException e) {
                    continue;
                }
                String tabName = profileTab.profileTabHandle.tabNameField.getText();
                if (tabName.equals(activeTabName) ) {
                    tabbedPane.setSelectedIndex(tabNum);
                }
            }
        }
    }
}
