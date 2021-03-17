package burp;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener {
    private JMenu menuButton;

    ConfigMenu() {
        Signing.callbacks.registerExtensionStateListener(this);
    }

    public void run() {
        menuButton = new JMenu("HTTP Signatures");
        menuButton.addMenuListener(this);
        JMenuBar burpMenuBar = ConfigSettings.getBurpFrame().getJMenuBar();

        if (burpMenuBar == null) {
            Signing.callbacks.printError("Unable to add HTTP Signatures menu button.");
        } else {
            burpMenuBar.add(menuButton);
        }
    }

    public void menuSelected(MenuEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                Signing.globalSettings.showSettings();
            }
        });
    }

    public void menuDeselected(MenuEvent e) {
    }

    public void menuCanceled(MenuEvent e) {
    }

    public void extensionUnloaded() {
        ConfigSettings.getBurpFrame().getJMenuBar().remove(menuButton);
    }
}
