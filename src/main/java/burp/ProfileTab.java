package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.LinkedHashMap;

public class ProfileTab extends JPanel {

    ProfileTabHandle profileTabHandle;
    JTabbedPane tabbedPane;
    private String profileConfig;
    private ConfigSettings configSettings;
    private String tabName;
    LinkedHashMap<String, Object> newProfile;

    ProfileTab(String _tabName, ConfigSettings _configSettings, String _profileConfig) {
        this.tabName = _tabName;
        configSettings = _configSettings;
        tabbedPane = configSettings.tabbedPane;
        profileTabHandle = new ProfileTabHandle(tabName, configSettings, this);
        profileConfig = _profileConfig;

        String[] valuesParts = profileConfig.split(";");
        newProfile = new LinkedHashMap<>();

        setLayout(new SpringLayout());
        int i = 0;
        for (String key : configSettings.settings.keySet()) {
            String value = "";
            // if valuesParts has only one value; we use the default configuration settings (e.g. new tab)
            if (valuesParts.length == 1) {
                value = _configSettings.settings.get(key);
            } else {
                if (i+1 > valuesParts.length) {
                    value = "";
                } else {
                    value = valuesParts[i];
                }
            }
            JLabel l = new JLabel(key, JLabel.TRAILING);
            add(l);
            JTextField textField = new JTextField(value);
            l.setLabelFor(textField);
            newProfile.put(key, textField);
            add(textField);
            i++;
        }

        // current version (11 rows): Header, keyId, private key, digest, get, head, delete, put, post, query, port
        makeCompactGrid(this,
                11, 2,    // rows, cols
                6, 6, // initX, initY
                6, 6);   // xPad, yPad
    }

    /**
     * The following two methods are from
     * https://docs.oracle.com/javase/tutorial/uiswing/layout/spring.html
     */

    /* Used by makeCompactGrid. */
    private SpringLayout.Constraints getConstraintsForCell(
            int row, int col,
            Container parent,
            int cols) {
        SpringLayout layout = (SpringLayout) parent.getLayout();
        Component c = parent.getComponent(row * cols + col);
        return layout.getConstraints(c);
    }

    /**
     * Aligns the first <code>rows</code> * <code>cols</code>
     * components of <code>parent</code> in
     * a grid. Each component in a column is as wide as the maximum
     * preferred width of the components in that column;
     * height is similarly determined for each row.
     * The parent is made just big enough to fit them all.
     *
     * @param rows     number of rows
     * @param cols     number of columns
     * @param initialX x location to start the grid at
     * @param initialY y location to start the grid at
     * @param xPad     x padding between cells
     * @param yPad     y padding between cells
     */
    private void makeCompactGrid(Container parent,
                                 int rows, int cols,
                                 int initialX, int initialY,
                                 int xPad, int yPad) {
        SpringLayout layout;
        try {
            layout = (SpringLayout) parent.getLayout();
        } catch (ClassCastException exc) {
            System.err.println("The first argument to makeCompactGrid must use SpringLayout.");
            return;
        }

        //Align all cells in each column and make them the same width.
        Spring x = Spring.constant(initialX);
        for (int c = 0; c < cols; c++) {
            Spring width = Spring.constant(0);
            for (int r = 0; r < rows; r++) {
                width = Spring.max(width,
                        getConstraintsForCell(r, c, parent, cols).
                                getWidth());
            }
            for (int r = 0; r < rows; r++) {
                SpringLayout.Constraints constraints =
                        getConstraintsForCell(r, c, parent, cols);
                constraints.setX(x);
                constraints.setWidth(width);
            }
            x = Spring.sum(x, Spring.sum(width, Spring.constant(xPad)));
        }

        //Align all cells in each row and make them the same height.
        Spring y = Spring.constant(initialY);
        for (int r = 0; r < rows; r++) {
            Spring height = Spring.constant(0);
            for (int c = 0; c < cols; c++) {
                height = Spring.max(height,
                        getConstraintsForCell(r, c, parent, cols).
                                getHeight());
            }
            for (int c = 0; c < cols; c++) {
                SpringLayout.Constraints constraints =
                        getConstraintsForCell(r, c, parent, cols);
                constraints.setY(y);
                constraints.setHeight(height);
            }
            y = Spring.sum(y, Spring.sum(height, Spring.constant(yPad)));
        }

        //Set the parent's size.
        SpringLayout.Constraints pCons = layout.getConstraints(parent);
        pCons.setConstraint(SpringLayout.SOUTH, y);
        pCons.setConstraint(SpringLayout.EAST, x);
    }

    Component getTabHandleElement() {
        return profileTabHandle;
    }

    public String getTabName() {
        return tabName;
    }

    public String getProfileConfig() {
        return profileConfig;
    }

    public LinkedHashMap<String, Object> getNewProfile() {
        return newProfile;
    }

    static class ProfileTabHandle extends JPanel {
        private JTabbedPane parentTabbedPane;
        ProfileTab profileTab;
        JTextField tabNameField;
        JButton closeButton;
        private ConfigSettings configSettings;

        private ProfileTabHandle(String tabName, ConfigSettings _configSettings, ProfileTab profileTab) {
            this.configSettings = _configSettings;
            this.profileTab = profileTab;
            this.parentTabbedPane = configSettings.tabbedPane;
            this.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
            this.setOpaque(false);
            JLabel label = new JLabel(tabName);
            label.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));

            tabNameField = new JTextField(tabName);
            tabNameField.setOpaque(false);
            tabNameField.setBorder(null);
            tabNameField.setBackground(new Color(0, 0, 0, 0));
            tabNameField.setEditable(false);
            tabNameField.setCaretColor(Color.BLACK);
            this.add(tabNameField);

            closeButton = new JButton("✕");
            closeButton.setFont(new Font("monospaced", Font.PLAIN, 10));
            closeButton.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
            closeButton.setForeground(Color.GRAY);
            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);
            closeButton.setOpaque(false);

            tabNameField.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    parentTabbedPane.setSelectedComponent(profileTab);
                    if (SwingUtilities.isRightMouseButton(e)) {
                        parentTabbedPane.dispatchEvent(e);
                    } else if (SwingUtilities.isMiddleMouseButton(e)) {
                        configSettings.closeTab(profileTab);
                    } else if (e.getClickCount() >= 2) {
                        tabNameField.setEditable(true);
                    }
                }
            });

            tabNameField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    tabNameField.setEditable(false);
                    // Add a single space to an empty name to keep it selectable for editing
                    if (tabNameField.getText().isEmpty()) {
                        tabNameField.setText(" ");
                    }
                    super.focusLost(e);
                }
            });

            closeButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        parentTabbedPane.setSelectedComponent(profileTab);
                        parentTabbedPane.dispatchEvent(e);
                    } else {
                        configSettings.closeTab(profileTab);
                    }
                }
            });

            this.add(closeButton);
        }
    }
}
