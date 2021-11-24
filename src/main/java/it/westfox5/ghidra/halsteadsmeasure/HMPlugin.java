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
package it.westfox5.ghidra.halsteadsmeasure;

import java.io.File;
import java.io.IOException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import it.westfox5.ghidra.halsteadsmeasure.calculator.HMCalculator;
import it.westfox5.ghidra.halsteadsmeasure.calculator.HMCalculatorFactory;
import it.westfox5.ghidra.halsteadsmeasure.export.HMExporter;
import it.westfox5.ghidra.halsteadsmeasure.export.HMExporterFactory;

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
public class HMPlugin extends ProgramPlugin {	

	/**** ALLOWED CHANGES ****/
	private static Boolean DEBUG = false;
	/**** END ALLOWED CHANGES SECTION****/
	
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public HMPlugin(PluginTool tool) {
		super(tool, false, false);
		
		createActions();
	}
	
	public HalsteadsMeasure calculateForMainFunction() throws HMException {
		
		// function calculator
		String functionName = "main";
		HMCalculator calculator = HMCalculatorFactory.functionCalculator(this, functionName);

		HalsteadsMeasure hm = calculator.getHalsteadMeasures();
		if (hm == null) throw new HMException("Cannot calculate Halstead's Measures for function `"+functionName+"`");
		return hm;
	}
	
	public File exportToJSONFile(HalsteadsMeasure hm) throws HMException, IOException {
		String filename = "halsteads_measure";
		HMExporter exporter = HMExporterFactory.jsonExporter(filename);
		return exporter.export(hm);
	}

	
	private void createActions() {
		final HMPlugin plugin = this;
		
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
				} catch(HMException e) {
					e.printStackTrace();
					plugin.errorMsg(this, e.getMessage());
				}
			

				// TODO find a way to create dialogs (@see Msg.showInfo)
				infoMsg(plugin,
				"\n" + 	"---- Halstead's Measures ----------------------------"   + "\n" +
						" Unique operators (n1):\t"+ hm.getNumDistinctOperators() + "\n" +//: \n" + uniqueOpStr);
						" Unique operands  (n2):\t"+ hm.getNumDistinctOperands()  + "\n" +//: \n" + uniqueOpndStr);
						" Total operators  (N1):\t"+ hm.getNumOperators()         + "\n" +
						" Total operands   (N2):\t"+ hm.getNumOperands()          + "\n" +
						"-----------------------------------------------------"   + "\n" // put "(HMPlugin)" in new line
					);
				
				// DUMP MEASURES TO FILE
				try {
					File file = exportToJSONFile(hm);
					infoMsg(plugin, "Successfully dumped data to `"+file.getAbsolutePath()+"`.");
				} catch (HMException | IOException e) {
					e.printStackTrace();
					plugin.errorMsg(this, e.getMessage());

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

	/* convenience method for debugging */
	public void debugMsg(Object originator, Object msg) {
		if (DEBUG) infoMsg(originator, msg);
	}
	/* convenience method for info msg reporting */
	public void infoMsg(Object originator, Object msg) {
		Msg.info(originator, msg);
	}
	/* convenience method for error msg reporting */
	public void errorMsg(Object originator, Object msg) {
		Msg.error(originator, msg);
	}
}
