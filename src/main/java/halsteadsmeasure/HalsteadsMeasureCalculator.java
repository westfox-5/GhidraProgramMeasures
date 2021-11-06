package halsteadsmeasure;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableFilter;

public class HalsteadsMeasureCalculator {
	private final HalsteadsMeasurePlugin plugin;
	
	private Function mainFn;
	private boolean canDo;
	
	public HalsteadsMeasureCalculator(HalsteadsMeasurePlugin plugin) {
		this.plugin = plugin;
	}
	
	public Function getMainFunction() {
		initMainFunction();
		return mainFn;
	}

	private void initMainFunction() {
		// lazy loader
		if (mainFn == null) {
			canDo = true;
			List<Function> mainFns = plugin.getCurrentProgram().getListing().getGlobalFunctions("main");
			if (!(mainFns != null && !mainFns.isEmpty())) {
				plugin.errorMsg(this, "No `main` function found in current program.");
				canDo = false;
				return;
			}
			if (mainFns.size() > 1) {
				plugin.errorMsg(this, "More than 1 `main` function found in current program.");
				canDo = false;
				return;
			}
			
			this.mainFn = mainFns.iterator().next();
		}
	}
	
	
	public void calculate() {
		initMainFunction();
		if (!canDo) return;
		
		plugin.infoMsg(this, "Found `main` function at `"+mainFn.getEntryPoint()+"`");
		
		Variable[] localVariables = mainFn.getLocalVariables();
		int numLocalVariables = localVariables != null ? localVariables.length : 0;
		
		AddressIterator addresses = mainFn.getBody().getAddresses(true);
		while(addresses.hasNext()) {
			Address addr = addresses.next();
			Instruction instr = plugin.getCurrentProgram().getListing().getInstructionAt(addr);
			
			/* INSTR OP STRING */
			//instr.getMnemonicString();
			
			/* INSTR PARAM STRING  -- from 0 to numOperands */
			// instr.getDefaultOperandRepresentation(0);
			
			// instr.getNumOperands()
			
			plugin.infoMsg(this, instr);
		}
	}
}
