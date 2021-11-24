/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.westfox5.ghidra.halsteadsmeasure.plugin;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.calculator.CalculationException;
import it.westfox5.ghidra.calculator.Calculator;
import it.westfox5.ghidra.calculator.CalculatorFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.ExporterFactory;
import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;
import it.westfox5.ghidra.util.logger.Logger;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class HalsteadsMeasurePlugin extends ProgramPlugin {	
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public HalsteadsMeasurePlugin(PluginTool tool) {
		super(tool, false, false);
		
		createActions();
	}
	
	public HalsteadsMeasure calculateForMainFunction() throws CalculationException {
		
		// function calculator
		Program program = getCurrentProgram();
		String functionName = "main";
		Calculator calculator = CalculatorFactory.functionCalculator(program, functionName);

		HalsteadsMeasure hm = calculator.getHalsteadMeasures();
		if (hm == null) throw new CalculationException("Cannot calculate Halstead's Measures for function `"+functionName+"`");
		return hm;
	}
	
	public File exportToJSONFile(HalsteadsMeasure hm) throws ExportException {
		String filename = "halsteads_measure";
		Exporter exporter = ExporterFactory.jsonExporter(filename);
		return exporter.export(hm);
	}

	
	private void createActions() {
		final HalsteadsMeasurePlugin plugin = this;
		
		DockingAction action = new DockingAction("Calculate Halstead's Measures", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				
				/*
				 *	ATTENTION
				 *	the body of this function is essentially used for 
				 *  testing purposes!
				 *  
				 *  all the hard-coded functions can be easily generalized/parameterized when all is functioning
				 * 
				 */
				
				// LOAD MEASURES FROM PROGRAM
				HalsteadsMeasure hm = null;
				try {
					hm = plugin.calculateForMainFunction();
				
				
	
					// TODO find a way to create dialogs (@see Msg.showInfo)
					Logger.msgLogger.info(this,
					"\n" + 	"---- Halstead's Measures ----------------------------"   + "\n" +
							" Unique operators (n1):\t"+ hm.getNumDistinctOperators() + "\n" +//: \n" + uniqueOpStr);
							" Unique operands  (n2):\t"+ hm.getNumDistinctOperands()  + "\n" +//: \n" + uniqueOpndStr);
							" Total operators  (N1):\t"+ hm.getNumOperators()         + "\n" +
							" Total operands   (N2):\t"+ hm.getNumOperands()          + "\n" +
							"-----------------------------------------------------"   + "\n" // put "(HMPlugin)" in new line
						);
					
					// DUMP MEASURES TO FILE
				
					exportToJSONFile(hm);
					
					
				} catch (CalculationException | ExportException e) {
					e.printStackTrace();
					Logger.msgLogger.err(this, e.getMessage());

				} 
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		action.setEnabled(true);
		// TODO externalize strings
		action.setMenuBarData(new MenuData(new String[] { "Window", "Halstead's Measures" }));
		tool.addAction(action);
	}
}
