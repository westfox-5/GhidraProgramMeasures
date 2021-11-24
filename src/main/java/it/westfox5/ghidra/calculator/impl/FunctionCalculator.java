package it.westfox5.ghidra.calculator.impl;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.calculator.Calculator;
import it.westfox5.ghidra.calculator.CalculationException;
import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;
import it.westfox5.ghidra.util.StringUtils;
import it.westfox5.ghidra.util.logger.Logger;

public class FunctionCalculator implements Calculator {
	private static final String RET_INSTR_MNEMONIC_STR = "RET";

	private final String fnName;
	private final Program program;
	
	public FunctionCalculator(Program program, String functionName) {
		this.program = program;
		this.fnName = functionName;	
	}
	
	private Function findFunction() {
		if (StringUtils.isEmpty(fnName)) {
			Logger.msgLogger.err(this, "No function name provided");
			return null;
		}
		
		if (program == null) {
			Logger.msgLogger.err(this, "No program provided");
			return null;
		}
		
		List<Function> fns = program.getListing().getGlobalFunctions(fnName);
		if (!(fns != null && !fns.isEmpty())) {
			Logger.msgLogger.err(this, "No function found in current program with name `"+fnName+"`.");
			return null;
		}
		if (fns.size() > 1) {
			Logger.msgLogger.err(this, "More than 1 function found in current program with name `"+fnName+"`.");
			return null;
		}
		
		// fns.size() == 1
		return fns.iterator().next();
	}
	
	
	public HalsteadsMeasure getHalsteadMeasures() throws CalculationException{
		HalsteadsMeasure.Builder builder = HalsteadsMeasure.make(program);
		
		Function function = findFunction();
		if (function == null) {
			return builder.build();
		}
		
		Logger.msgLogger.debug(this, "###################### START PARSING `"+fnName+"` [entry_point: `"+function.getEntryPoint()+"`] ######################");

		Listing listing = program.getListing();
		
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
					throw new CalculationException("Empty operator found at addr: '"+instr.getAddressString(false, true)+"'");
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
						throw new CalculationException("Empty operand found at addr: '"+instr.getAddressString(false, true)+"'");
					}
					
					builder.addOperand(opnd, instr);
				}
			}
			
			Logger.msgLogger.debug(this, instr);
		}
		
		Logger.msgLogger.debug(this, "###################### END PARSING `"+fnName+"` [num_instructions:"+numInstructions+"] ######################");
		
		return builder.build();
	}
}