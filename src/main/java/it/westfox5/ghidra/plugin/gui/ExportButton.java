package it.westfox5.ghidra.plugin.gui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Path;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;

import docking.ComponentProvider;
import ghidra.util.Msg;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.plugin.ProgramMeasuresPlugin;

public class ExportButton extends JButton {
	
	public ExportButton(final ProgramMeasuresPlugin plugin, final ExportType exportType) {
		super("Export as JSON");
		
		addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JComponent parentComponent = plugin.getProvider().getComponent();

				final JFileChooser fc = new JFileChooser();
				int response = fc.showSaveDialog(parentComponent);
				
				if (response == JFileChooser.APPROVE_OPTION) {
					
							
					try {
						Path destPath = fc.getSelectedFile().toPath();
						File file = plugin.getService().exportAs(destPath, exportType);
						if (file.exists()) {
							Msg.showInfo(getClass(), parentComponent, "Export completed", "File saved at "+ file.getAbsolutePath());
						}
						
					} catch(ExportException ee) {
						ee.printStackTrace();
						Msg.showError(this, parentComponent, ComponentProvider.DEFAULT_WINDOW_GROUP, ee.getMessage());
					}
				}
			}
		});
	}

	
	
}
