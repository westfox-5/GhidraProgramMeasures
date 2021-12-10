package it.westfox5.ghidra.plugin;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;
import it.westfox5.ghidra.plugin.gui.ExportButton;
import it.westfox5.ghidra.util.logger.Logger;
import resources.Icons;

public class ProgramMeasuresProvider extends ComponentProvider {
	
	private static final String NAME = "Program Measures Calculator";
	
	private final ProgramMeasuresPlugin plugin;
	
	/* GUI ELEMENTS*/
	private JPanel panel;
	private JTextArea textArea;
	private JButton btnExportJSON;
	
	public ProgramMeasuresProvider(ProgramMeasuresPlugin plugin) {
		super(plugin.getTool(), NAME, plugin.getName());
		this.plugin = plugin;
		
		buildComponent();
		
		setWindowMenuGroup(ProgramMeasuresPlugin.NAME);
		setWindowGroup(ProgramMeasuresPlugin.NAME);
		setDefaultWindowPosition(WindowPosition.WINDOW);
		
		addToTool();

		createActions();
	}

	public void dispose() {
		plugin.getService().reinitialize();
		
		buildComponent();
	}
	

	@Override
	public void componentShown() {
		installData();
	}
	
	@Override
	public void closeComponent() {
		dispose();
	}

	// Customize GUI
	// TODO Externalize UI to a separate class
	private void buildComponent() {
		//panel = new JPanel(new GridLayout(0, 1)); // as many rows as needed
		panel = new JPanel(new BorderLayout());
		panel.setSize(new Dimension(150, 75));
		
		textArea = new JTextArea(10, 50);
		textArea.setDisabledTextColor(Color.RED);
		textArea.setEditable(false);
		
		btnExportJSON = new ExportButton(plugin, ExportType.JSON);
		
		panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
		panel.add(btnExportJSON, BorderLayout.AFTER_LAST_LINE);
	}
	
	private void installData() {
		Halstead halstead = null;

		try {
			halstead = plugin.getService().getOrCreate();

		} catch (AnalysisException e) {
			Logger.msgLogger.err(plugin, e.getMessage());
		}
		
		// validate
		if (halstead == null) {
			Logger.msgLogger.err(plugin, "Program analysis failed");
			Function f = plugin.getService().getFunction();
			textArea.setText("Unable to perform the analysis on the program" + (f != null ? " for function `"+f.getName()+"`" : "") +".\n"
					+ "Please select another function in the program listing and click on the reload button.");
			
			textArea.setEnabled(false);
			btnExportJSON.setEnabled(false);
			return;
		}

		// submit
	    textArea.setText(
    		"--- Halstead's Measures -- SUMMARY ------------------"         + "\n" +
    		" Unique operators (n1):\t"+ halstead.getNumDistinctOperators() + "\n" +
    		" Unique operands  (n2):\t"+ halstead.getNumDistinctOperands()  + "\n" +
    		" Total operators  (N1):\t"+ halstead.getNumOperators() + "\n" +
    		" Total operands   (N2):\t"+ halstead.getNumOperands() + "\n" +
    		"-----------------------------------------------------" + "\n");
	    
	    textArea.setEnabled(true);
		btnExportJSON.setEnabled(true);
	}
	
	void locationChanged(ProgramLocation loc) {
		if (loc == null) 
			return;
		
		if (!isVisible())
			return;
		
		Program p = loc.getProgram();
		Function f = p.getFunctionManager().getFunctionContaining(loc.getAddress());
		
		plugin.getService().updateLoc(p, f);
	}

	private void createActions() {
		DockingAction action = new DockingAction("Reload from current location", getName()) {
			
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.getService().reinitialize();
				updateTitle();
				installData();
			}
		};
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		addLocalAction(action);
	}
	
	private void updateTitle() {
		Function function = plugin.getService().getFunction();
		if (function != null) {
			setSubTitle("Function: " + function.getName());
		}
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
