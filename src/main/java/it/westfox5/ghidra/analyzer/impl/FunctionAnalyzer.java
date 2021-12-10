package it.westfox5.ghidra.analyzer.impl;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;
import it.westfox5.ghidra.util.StringUtils;
import it.westfox5.ghidra.util.logger.Logger;

public class FunctionAnalyzer extends Analyzer {
	private static final String RET_INSTR_MNEMONIC_STR = "RET";

	private final Function function;
	
	public FunctionAnalyzer(Program program, Function function) {
		super(program);
		this.function = function;	
	}
	
	@Override
	public Halstead getHalsteadMeasures() throws AnalysisException{
		Halstead.Builder builder = Halstead.make(program);
		
		if (function == null) {
			return builder.build();
		}
		
		Logger.msgLogger.debug(this, "###################### START PARSING `"+function.getName()+"` [entry_point: `"+function.getEntryPoint()+"`] ######################");

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
			
			//Logger.msgLogger.debug(this, instr);
		}
		
		Logger.msgLogger.debug(this, "###################### END PARSING `"+function.getName()+"` [num_instructions:"+numInstructions+"] ######################");
		
		if (numInstructions == 0) {
			Logger.msgLogger.info(this, "The parsing of `"+function.getName()+"` failed. Maybe the program is not analyzed yet.");

			return null;
		}
		
		return builder.build();
	}
}