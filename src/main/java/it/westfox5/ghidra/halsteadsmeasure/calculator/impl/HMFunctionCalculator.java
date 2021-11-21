package it.westfox5.ghidra.halsteadsmeasure.calculator.impl;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import it.westfox5.ghidra.halsteadsmeasure.HMException;
import it.westfox5.ghidra.halsteadsmeasure.HMPlugin;
import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;
import it.westfox5.ghidra.halsteadsmeasure.calculator.HMCalculator;
import it.westfox5.ghidra.halsteadsmeasure.util.StringUtils;

public class HMFunctionCalculator implements HMCalculator {
	private static final String RET_INSTR_MNEMONIC_STR = "RET";
	
	private final HMPlugin plugin;
	private final String fnName;
	
	public HMFunctionCalculator(HMPlugin plugin, String functionName) {
		this.plugin = plugin;
		this.fnName = functionName;
		
	}
	
	private Function findFunction() {
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
	
	
	public HalsteadsMeasure getHalsteadMeasures() throws HMException{
		HalsteadsMeasure.Builder builder = HalsteadsMeasure.make();
		
		Function function = findFunction();
		if (function == null) {
			return builder.build();
		}
		
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
				if (StringUtils.isEmpty(op)) {
					throw new HMException("Empty operator found at addr: '"+instr.getAddressString(false, true)+"'");
				}

				if (RET_INSTR_MNEMONIC_STR.equals(op)) {
					retInstructionFound = true; 				// STOP 
				}
				
				builder.addOperator(op, instr);
			}
			
			
			{ /* OPERANDS */
				int numOperands = instr.getNumOperands();
				String opnd;
				for (int i=0;i<numOperands;i++) {
					opnd = instr.getDefaultOperandRepresentation(i);
					if (StringUtils.isEmpty(opnd)) { 
						throw new HMException("Empty operand found at addr: '"+instr.getAddressString(false, true)+"'");
					}
					
					builder.addOperand(opnd, instr);
				}
			}
			
			plugin.debugMsg(this, instr);
		}
		
		plugin.debugMsg(this, "###################### END PARSING `"+fnName+"` [num_instructions:"+numInstructions+"] ######################");
		
		return builder.build();
	}
}