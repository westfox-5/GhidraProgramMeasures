package halsteadsmeasure;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import halsteadsmeasure.util.StringUtils;

public class HalsteadsMeasureCalculator {
	private static final String RET_INSTR_MNEMONIC_STR = "RET";
	
	private final HalsteadsMeasurePlugin plugin;
	
	public HalsteadsMeasureCalculator(HalsteadsMeasurePlugin plugin) {
		this.plugin = plugin;
	}
	
	private Function findFunction(String fnName) {
		if (StringUtils.isEmpty(fnName)) {
			return null;
		}
		
		List<Function> fns = plugin.getCurrentProgram().getListing().getGlobalFunctions(fnName);
		if (!(fns != null && !fns.isEmpty())) {
			plugin.errorMsg(this, "No function found in current program with name `"+fnName+"`.");
			return null;
		}
		if (fns.size() > 1) {
			plugin.errorMsg(this, "More than 1 function found in current program with name `"+fnName+"`.");
			return null;
		}
		
		// fns.size() == 1
		return fns.iterator().next();
	}
	
	
	public HalsteadsMeasure calculateForFunction(String fnName) {
		HalsteadsMeasure hm = new HalsteadsMeasure();
		
		Function function = findFunction(fnName);
		if (function == null) 
			return hm;
		
		plugin.debugMsg(this, "###################### START PARSING `"+fnName+"` [entry_point: `"+function.getEntryPoint()+"`] ######################");

		Listing listing = plugin.getCurrentProgram().getListing();
		
		//Variable[] localVariables = mainFn.getLocalVariables();
		//int numLocalVariables = localVariables != null ? localVariables.length : 0;
		
		// get instructions starting @ the function entry point
		InstructionIterator instructions = listing.getInstructions(function.getEntryPoint(), true);
		boolean retInstructionFound = false;
		int numInstructions = 0;
		while (instructions.hasNext() && !retInstructionFound) {
			Instruction instr = instructions.next();
			numInstructions++;
			
			{ /* OPERATOR */
				String op = instr.getMnemonicString();
				// TODO is this check needed?
				if (StringUtils.isEmpty(op)) {
					continue;
				}

				if (RET_INSTR_MNEMONIC_STR.equals(op)) {
					retInstructionFound = true; 				// STOP 
				}
				
				hm.addOperator(op, instr);
			}
			
			
			{ /* OPERANDS */
				int numOperands = instr.getNumOperands();
				String opnd;
				for (int i=0;i<numOperands;i++) {
					opnd = instr.getDefaultOperandRepresentation(i);
					// TODO is this check needed?
					if (StringUtils.isEmpty(opnd)) { 
						continue;
					}
					
					hm.addOperand(opnd, instr);
				}
			}
			
			plugin.debugMsg(this, instr);
		}
		
		plugin.debugMsg(this, "###################### END PARSING `"+fnName+"` [num_instructions:"+numInstructions+"] ######################");
		
		return hm;
	}
}