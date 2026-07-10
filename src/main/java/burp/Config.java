package burp;

import yaml.YamlUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Config {
    private JPanel one;
    private JTextField txtfield1;
    private JTextArea hostFilterTextArea;
    public String yaml_path = BurpExtender.Yaml_Path;
    public JSpinner spinner1;
    private BurpExtender burp;
    public JTabbedPane ruleTabbedPane;
    public TabTitleEditListener ruleSwitch;
    protected static JPopupMenu tabMenu = new JPopupMenu();
    private JMenuItem closeTabMenuItem = new JMenuItem("Delete");
    private static int RulesInt = 0;
    private static final Dimension BUTTON_SIZE = new Dimension(96, 28);

    public static String new_Rules() {
        RulesInt += 1;
        return "New " + RulesInt;
    }

    public void newTab() {
        Object[][] data = new Object[][]{{false, "New Name", "(New Regex)", "gray", "any", "nfa", false}};
        insertTab(ruleTabbedPane, Config.new_Rules(), data);
    }

    public void insertTab(JTabbedPane pane, String title, Object[][] data) {
        pane.addTab(title, new JLabel());
        pane.remove(pane.getSelectedIndex());
        pane.addTab("...", new JLabel());
    }

    public Config(BurpExtender burp) {
        tabMenu.removeAll();
        tabMenu.add(closeTabMenuItem);
        closeTabMenuItem.addActionListener(e -> closeTabActionPerformed(e));
        this.burp = burp;
    }

    public void closeTabActionPerformed(ActionEvent e) {
        if (ruleTabbedPane.getTabCount() <= 2 || isAddTabSelected()) {
            return;
        }
        String type = selectedRuleType();
        if (confirm("Are you sure you want to delete this tab?")) {
            View removeView = burp.views.get(type);
            if (removeView != null) {
                for (View.LogEntry l : removeView.log) {
                    YamlUtil.removeYaml(l.id, BurpExtender.Yaml_Path);
                }
            }
            Bfunc.show_yaml(burp);
        }
    }

    private void $$$setupUI$$$() {
        one = new JPanel(new BorderLayout(8, 8));
        one.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        one.add(buildTopPanel(), BorderLayout.NORTH);
        one.add(buildRulesPanel(), BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridy = 0;
        gbc.gridx = 0;

        JButton onOffButton = createButton("Start");
        Color primary = onOffButton.getBackground();
        on_off_Button_action(onOffButton, primary);
        topPanel.add(onOffButton, gbc);

        gbc.gridx++;
        JButton carryHeadButton = createButton(burp.Carry_head ? "Head Off" : "Head On");
        if (burp.Carry_head) {
            carryHeadButton.setBackground(Color.green);
        }
        carry_head_Button_action(carryHeadButton, primary);
        topPanel.add(carryHeadButton, gbc);

        gbc.gridx++;
        topPanel.add(new JLabel("Threads:"), gbc);
        gbc.gridx++;
        SpinnerNumberModel model1 = new SpinnerNumberModel(10, 1, 500, 1);
        this.spinner1 = new JSpinner(model1);
        configureThreadSpinner();
        topPanel.add(spinner1, gbc);

        gbc.gridx++;
        gbc.weightx = 1;
        topPanel.add(Box.createHorizontalGlue(), gbc);

        gbc.gridy = 1;
        gbc.gridx = 0;
        gbc.weightx = 0;
        topPanel.add(new JLabel("Yaml File Path:"), gbc);

        gbc.gridx++;
        gbc.gridwidth = 3;
        gbc.weightx = 1;
        txtfield1 = new JTextField(yaml_path);
        txtfield1.setEditable(false);
        topPanel.add(txtfield1, gbc);

        gbc.gridx += 3;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        JButton loadButton = createButton("Load Yaml");
        load_button_Yaml(loadButton);
        topPanel.add(loadButton, gbc);

        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        topPanel.add(new JLabel("Filter_Host:"), gbc);

        gbc.gridx = 1;
        gbc.gridwidth = 4;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        hostFilterTextArea = new JTextArea("*", 4, 20);
        hostFilterTextArea.setLineWrap(false);
        hostFilterTextArea.setToolTipText("One host rule per line. Wildcard * is supported, for example: *.example.com");
        JScrollPane hostScrollPane = new JScrollPane(hostFilterTextArea);
        hostScrollPane.setPreferredSize(new Dimension(320, 76));
        burp.Host_textarea = hostFilterTextArea;
        topPanel.add(hostScrollPane, gbc);

        return topPanel;
    }

    private JPanel buildRulesPanel() {
        JPanel rulesPanel = new JPanel(new BorderLayout(8, 0));

        JPanel actionPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(0, 0, 4, 0);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton addButton = createButton("Add");
        Add_Button_Yaml(addButton, yaml_path);
        actionPanel.add(addButton, gbc);

        gbc.gridy++;
        JButton editButton = createButton("Edit");
        Edit_Button_Yaml(editButton, yaml_path);
        actionPanel.add(editButton, gbc);

        gbc.gridy++;
        JButton removeButton = createButton("Del");
        Del_Button_Yaml(removeButton, yaml_path);
        actionPanel.add(removeButton, gbc);

        gbc.gridy++;
        gbc.weighty = 1;
        actionPanel.add(Box.createVerticalGlue(), gbc);

        ruleTabbedPane = new JTabbedPane();
        this.ruleSwitch = new TabTitleEditListener(ruleTabbedPane, this.burp);
        Bfunc.show_yaml(burp);
        ruleTabbedPane.addMouseListener(ruleSwitch);

        rulesPanel.add(actionPanel, BorderLayout.WEST);
        rulesPanel.add(ruleTabbedPane, BorderLayout.CENTER);
        return rulesPanel;
    }

    private JButton createButton(String text) {
        JButton button = new JButton(text);
        button.setPreferredSize(BUTTON_SIZE);
        button.setMinimumSize(BUTTON_SIZE);
        return button;
    }

    private void configureThreadSpinner() {
        JFormattedTextField textField = ((JSpinner.DefaultEditor) this.spinner1.getEditor()).getTextField();
        textField.setEditable(true);
        textField.setColumns(4);
        this.spinner1.addChangeListener(e -> burp.resizeThreadPool(getThreadCount()));
        textField.addActionListener(e -> applyThreadCountFromEditor());
        textField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                applyThreadCountFromEditor();
            }
        });
    }

    private void applyThreadCountFromEditor() {
        int value = getThreadCount();
        if (!spinner1.getValue().equals(Integer.valueOf(value))) {
            spinner1.setValue(value);
        }
        burp.resizeThreadPool(value);
    }

    public int getThreadCount() {
        if (spinner1 == null) {
            return 10;
        }
        try {
            spinner1.commitEdit();
        } catch (ParseException ignored) {
        }
        Object value = spinner1.getValue();
        int threads;
        if (value instanceof Number) {
            threads = ((Number) value).intValue();
        } else {
            threads = 10;
        }
        return Math.max(1, Math.min(500, threads));
    }

    private void carry_head_Button_action(JButton button, Color primary) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.Carry_head) {
                    burp.Carry_head = false;
                    button.setText("Head On");
                    button.setBackground(primary);
                } else {
                    burp.Carry_head = true;
                    button.setText("Head Off");
                    button.setBackground(Color.green);
                }
            }
        });
    }

    private void on_off_Button_action(JButton button, Color primary) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.on_off) {
                    burp.on_off = false;
                    button.setText("Start");
                    button.setBackground(primary);
                } else {
                    burp.on_off = true;
                    button.setText("Stop");
                    button.setBackground(Color.green);
                }
            }
        });
    }

    private void Edit_Button_Yaml(JButton button, String yamlPath) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String type = selectedRuleType();
                View viewClass = burp.views.get(type);
                if (viewClass == null || viewClass.Choice == null) {
                    burp.prompt(one, "Please select a rule first.");
                    return;
                }
                showRuleDialog(type, viewClass, viewClass.Choice, yamlPath);
            }
        });
    }

    private void Del_Button_Yaml(JButton button, String yamlPath) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String type = selectedRuleType();
                View viewClass = burp.views.get(type);
                if (viewClass == null || viewClass.Choice == null) {
                    return;
                }
                if (confirm("Are you sure you want to delete this rule?")) {
                    YamlUtil.removeYaml(viewClass.Choice.id, yamlPath);
                    Bfunc.show_yaml_view(burp, viewClass, type);
                }
            }
        });
    }

    private void Add_Button_Yaml(JButton button, String yamlPath) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String type = selectedRuleType();
                if (type == null || type.equals("...")) {
                    burp.prompt(one, "Please select or create a rule tab first.");
                    return;
                }
                showRuleDialog(type, burp.views.get(type), null, yamlPath);
            }
        });
    }

    private void showRuleDialog(String type, View viewClass, View.LogEntry choice, String yamlPath) {
        boolean editing = choice != null;
        RuleForm form = new RuleForm();
        if (editing) {
            form.nameText.setText(choice.name);
            form.methodCombo.setSelectedItem(choice.method);
            form.urlText.setText(choice.url);
            form.reText.setText(choice.re);
            form.infoText.setText(choice.info);
            form.stateText.setText(choice.state);
        }

        Window owner = SwingUtilities.getWindowAncestor(one);
        JDialog dialog = new JDialog(owner, editing ? "Edit Rule" : "Add Rule", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.getContentPane().setLayout(new BorderLayout(8, 8));
        dialog.getContentPane().add(form.panel, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("NO");
        buttons.add(cancelButton);
        buttons.add(okButton);
        dialog.getContentPane().add(buttons, BorderLayout.SOUTH);

        cancelButton.addActionListener(e -> dialog.dispose());
        okButton.addActionListener(e -> {
            Map<String, Object> rule = new HashMap<String, Object>();
            if (editing) {
                rule.put("id", Integer.parseInt(choice.id));
                rule.put("loaded", choice.loaded);
            } else {
                rule.put("id", nextRuleId(yamlPath));
                rule.put("loaded", true);
            }
            rule.put("type", type);
            rule.put("name", form.nameText.getText());
            rule.put("method", form.methodCombo.getSelectedItem());
            rule.put("url", form.urlText.getText());
            rule.put("re", form.reText.getText());
            rule.put("info", form.infoText.getText());
            rule.put("state", form.stateText.getText());

            if (editing) {
                YamlUtil.updateYaml(rule, yamlPath);
                Bfunc.show_yaml_view(burp, viewClass, type);
            } else {
                YamlUtil.addYaml(rule, yamlPath);
                Bfunc.show_yaml_view(burp, burp.views.get(type), type);
            }
            dialog.dispose();
        });

        dialog.pack();
        Dimension preferred = dialog.getPreferredSize();
        dialog.setMinimumSize(new Dimension(420, preferred.height));
        if (preferred.width < 420) {
            dialog.setSize(420, preferred.height);
        }
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private int nextRuleId(String yamlPath) {
        int id = 0;
        Map<String, Object> yamlMap = YamlUtil.readYaml(yamlPath);
        List<Map<String, Object>> rules = (List<Map<String, Object>>) yamlMap.get("Load_List");
        if (rules != null) {
            for (Map<String, Object> rule : rules) {
                Object value = rule.get("id");
                if (value instanceof Number && ((Number) value).intValue() > id) {
                    id = ((Number) value).intValue();
                }
            }
        }
        return id + 1;
    }

    private void load_button_Yaml(JButton button) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Bfunc.show_yaml(burp);
            }
        });
    }

    private boolean confirm(String message) {
        int option = JOptionPane.showConfirmDialog(one, message, "Tips", JOptionPane.YES_NO_OPTION);
        return option == JOptionPane.YES_OPTION;
    }

    private String selectedRuleType() {
        int index = ruleTabbedPane.getSelectedIndex();
        if (index < 0) {
            return null;
        }
        return ruleTabbedPane.getTitleAt(index);
    }

    private boolean isAddTabSelected() {
        String type = selectedRuleType();
        return "...".equals(type);
    }

    public JComponent $$$getRootComponent$$$() {
        if (one == null) {
            $$$setupUI$$$();
        }
        return one;
    }

    private static class RuleForm {
        private final JPanel panel = new JPanel(new GridBagLayout());
        private final JTextField nameText = new JTextField();
        private final JComboBox<String> methodCombo = new JComboBox<String>(new String[]{"GET", "POST"});
        private final JTextField urlText = new JTextField();
        private final JTextField reText = new JTextField();
        private final JTextField infoText = new JTextField();
        private final JTextField stateText = new JTextField();

        private RuleForm() {
            addRow(0, "Name :", nameText);
            addRow(1, "Method :", methodCombo);
            addRow(2, "Url :", urlText);
            addRow(3, "Re :", reText);
            addRow(4, "Info :", infoText);
            addRow(5, "State :", stateText);
        }

        private void addRow(int row, String label, JComponent field) {
            GridBagConstraints labelGbc = new GridBagConstraints();
            labelGbc.gridx = 0;
            labelGbc.gridy = row;
            labelGbc.insets = new Insets(4, 6, 4, 6);
            labelGbc.anchor = GridBagConstraints.WEST;
            panel.add(new JLabel(label), labelGbc);

            GridBagConstraints fieldGbc = new GridBagConstraints();
            fieldGbc.gridx = 1;
            fieldGbc.gridy = row;
            fieldGbc.insets = new Insets(4, 0, 4, 6);
            fieldGbc.fill = GridBagConstraints.HORIZONTAL;
            fieldGbc.weightx = 1;
            panel.add(field, fieldGbc);
        }
    }
}
