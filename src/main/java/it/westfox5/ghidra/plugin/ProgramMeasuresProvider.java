package it.westfox5.ghidra.plugin;

import java.awt.BorderLayout;
import java.io.File;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.util.Msg;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;
import resources.Icons;

public class ProgramMeasuresProvider extends ComponentProvider {
	
	private final ProgramMeasuresPlugin plugin;
	private JPanel panel;
	private JTextArea textArea;
	private DockingAction action;
	
	public ProgramMeasuresProvider(ProgramMeasuresPlugin plugin) {
		super(plugin.getTool(), "ProgramMeasuresProvider", plugin.getName());
		this.plugin = plugin;
		
		buildComponent();

		createActions();
	}

	public void dispose() {
		// do nothing
	}
	
	@Override
	public void componentActivated() {
		fillTextArea();
	}
	
	// Customize GUI
	// TODO Externalize UI to a proper class
	private void buildComponent() {
		panel = new JPanel(new BorderLayout());
		
		textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		
		panel.add(new JScrollPane(textArea));
		setVisible(true);
	}
	
	private void fillTextArea() {
		Halstead halstead = plugin.get();
		
	    textArea.setText(
    		"---- Halstead's Measures ----------------------------"         + "\n" +
    		" Unique operators (n1):\t"+ halstead.getNumDistinctOperators() + "\n" +
    		" Unique operands  (n2):\t"+ halstead.getNumDistinctOperands()  + "\n" +
    		" Total operators  (N1):\t"+ halstead.getNumOperators() + "\n" +
    		" Total operands   (N2):\t"+ halstead.getNumOperands() + "\n" +
    		"-----------------------------------------------------" + "\n");
	}

	// Customize Actions
	private void createActions() {
		action = new DockingAction("Export as", getName()) {
			
			@Override
			public boolean isEnabled() {
				return true; //return plugin.getService().has();5
			}

			@Override
			public void actionPerformed(ActionContext context) {
				try {
					File file = plugin.getService().exportAs(ExportType.JSON);
					if (file.exists()) {
						Msg.showInfo(getClass(), panel, "Export completed", "File located @ "+ file.getAbsolutePath());
					}
				} catch(ExportException ee) {
					ee.printStackTrace();
					Msg.showError(this, panel, DEFAULT_WINDOW_GROUP, ee.getMessage());
				}
			}
		};
		action.setToolBarData(new ToolBarData(Icons.SAVE_AS, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		addLocalAction(action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
