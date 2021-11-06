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

	private HalsteadsMeasureCalculator calculator;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public HalsteadsMeasurePlugin(PluginTool tool) {
		super(tool, false, false);
		
		calculator = new HalsteadsMeasureCalculator(this);

		createActions();
	}

	
	private void createActions() {
		DockingAction action = new DockingAction("Calculate Halstead's Measures", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "START");
				
				calculator.calculate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		action.setEnabled(true);
		action.setMenuBarData(new MenuData(new String[] { "Window", "Halstead's Measures" }));
		tool.addAction(action);
	}

	
	protected void infoMsg(Object originator, Object msg) {
		Msg.info(originator, msg);
	}
	protected void errorMsg(Object originator, Object msg) {
		Msg.error(originator, msg);
	}
}
