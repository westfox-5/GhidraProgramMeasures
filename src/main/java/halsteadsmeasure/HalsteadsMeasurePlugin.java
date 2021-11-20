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
package halsteadsmeasure;

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

	/**** ALLOWED CHANGES ****/
	private static Boolean DEBUG = false;
	/**** END ALLOWED CHANGES SECTION****/
	
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public HalsteadsMeasurePlugin(PluginTool tool) {
		super(tool, false, false);

		createActions();
	}

	
	private void createActions() {
		final HalsteadsMeasurePlugin plugin = this;
		
		DockingAction action = new DockingAction("Calculate Halstead's Measures", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				HalsteadsMeasureCalculator calculator = new HalsteadsMeasureCalculator(plugin);

				String functionName = "main";
				HalsteadsMeasure hm = calculator.calculateForFunction(functionName);
				if (hm == null) return;
				
				// TODO implement proper serialization of tokens
				/*
				String uniqueOpStr = hm.getOpOccurrences().entrySet().stream()
					.map(entry -> { 
						List<Instruction> value = entry.getValue();
						String addrOfOcc = value.stream()
								.map(i -> i.getAddress().toString())
								.sorted()
								.collect(Collectors.joining(", "));
						return entry.getKey() + " - found @ ["+addrOfOcc+"] ";
					})
					.sorted()
					.collect(Collectors.joining("\n"));
				
				String uniqueOpndStr = hm.getOpndOccurrences().entrySet().stream()
					.map(entry -> { 
						List<Instruction> value = entry.getValue();
						String addrOfOcc = value.stream()
								.map(i -> i.getAddress().toString())
								.sorted()
								.collect(Collectors.joining(", "));
						return entry.getKey() + " - found @ ["+addrOfOcc+"] ";
					})
					.sorted()
					.collect(Collectors.joining("\n"));
				*/
				
				// TODO find a way to create dialogs (@see Msg.showInfo)
				infoMsg(plugin,
				"\n" + 	"---- Halstead's Measures ----------------------------"   + "\n" +
						" Unique operators (n1):\t"+ hm.getNumDistinctOperators() + "\n" +//: \n" + uniqueOpStr);
						" Unique operands  (n2):\t"+ hm.getNumDistinctOperands()  + "\n" +//: \n" + uniqueOpndStr);
						" Total operators  (N1):\t"+ hm.getNumTotalOperators()    + "\n" +
						" Total operands   (N2):\t"+ hm.getNumTotalOperands()     + "\n" +
						"-----------------------------------------------------"
					);
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
	protected void debugMsg(Object originator, Object msg) {
		if (DEBUG) infoMsg(originator, msg);
	}
	/* convenience method for info msg reporting */
	protected void infoMsg(Object originator, Object msg) {
		Msg.info(originator, msg);
	}
	/* convenience method for error msg reporting */
	protected void errorMsg(Object originator, Object msg) {
		Msg.error(originator, msg);
	}
}
