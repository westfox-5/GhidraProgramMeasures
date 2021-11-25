package it.westfox5.ghidra.analyzer.impl;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.halstead.Halstead;
import it.westfox5.ghidra.util.StringUtils;
import it.westfox5.ghidra.util.logger.Logger;

public class FunctionAnalyzer implements Analyzer {
	private static final String RET_INSTR_MNEMONIC_STR = "RET";

	private final String fnName;
	private final Program program;
	
	public FunctionAnalyzer(Program program, String functionName) {
		this.program = program;
		this.fnName = functionName;	
	}
	
	private Function findFunction() throws AnalysisException {
		if (StringUtils.isEmpty(fnName)) {
			throw new AnalysisException("No function name provided");
		}
		
		if (program == null) {
			throw new AnalysisException("No program provided");
		}
		
		List<Function> fns = program.getListing().getGlobalFunctions(fnName);
		if (!(fns != null && !fns.isEmpty())) {
			throw new AnalysisException("No function found in current program with name `"+fnName+"`.");
		}
		if (fns.size() > 1) {
			throw new AnalysisException("More than 1 function found in current program with name `"+fnName+"`.");
		}
		
		// fns.size() == 1
		return fns.iterator().next();
	}
	
	
	public Halstead getHalsteadMeasures() throws AnalysisException{
		Halstead.Builder builder = Halstead.make(program);
		
		Function function = findFunction();
		if (function == null) {
			return builder.build();
		}
		
		Logger.msgLogger.debug(this, "###################### START PARSING `"+fnName+"` [entry_point: `"+function.getEntryPoint()+"`] ######################");

		Listing listing = program.getListing();
		
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
					throw new AnalysisException("Empty operator found at addr: '"+instr.getAddressString(false, true)+"'");
				}

				if (RET_INSTR_MNEMONIC_STR.equals(op)) {
					retInstructionFound = true; // STOP 
				}
				
				builder.addOperator(op, instr);
			}
			
			
			{ /* OPERANDS */
				int numOperands = instr.getNumOperands();
				String opnd;
				for (int i=0;i<numOperands;i++) {
					opnd = instr.getDefaultOperandRepresentation(i);
					if (StringUtils.isEmpty(opnd)) { 
						throw new AnalysisException("Empty operand found at addr: '"+instr.getAddressString(false, true)+"'");
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