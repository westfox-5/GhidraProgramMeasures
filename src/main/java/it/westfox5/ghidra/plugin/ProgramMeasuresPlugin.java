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
package it.westfox5.ghidra.plugin;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;


//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Program Measures Calculator",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Calculate different measures over the program.",
	description = "This plugin is able to calculate measures over the given program and export them to a file. Only Halstead's Measures are implemented for now."
)
//@formatter:on
public final class ProgramMeasuresPlugin extends ProgramPlugin {

	public static final boolean DEBUG = false;
	
	static final String NAME = "Program Measures Calculator";
	static final String SHOW_PROVIDER_ACTION_NAME = "Display Measures";
	
	private ProgramMeasuresProvider provider;
	private ProgramMeasureService<Halstead> service;

	public ProgramMeasuresPlugin(PluginTool tool) {
		super(tool, true, false);
	}
	
	@Override
	protected void init() {
		service = new ProgramMeasureService<>(this, MeasuredProgram.HALSTEAD);
		
		provider = new ProgramMeasuresProvider(this);
		createActions();
	}
	
	private void createActions() {
		DockingAction showProviderAction = new DockingAction(SHOW_PROVIDER_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.setVisible(true);
			}
		};

		tool.addAction(showProviderAction);
	}

	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		provider.locationChanged(loc);
	}
	
	public ProgramMeasureService<Halstead> getService() {
		return service;
	}

	public ComponentProvider getProvider() {
		return provider;
	}
}
