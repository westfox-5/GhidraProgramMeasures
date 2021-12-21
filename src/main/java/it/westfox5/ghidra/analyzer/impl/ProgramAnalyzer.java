package it.westfox5.ghidra.analyzer.impl;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;
import it.westfox5.ghidra.util.StringUtils;
import it.westfox5.ghidra.util.logger.Logger;

public class ProgramAnalyzer extends Analyzer {

	public ProgramAnalyzer(Program program) {
		super(program);
	}

	@Override
	public Halstead getHalsteadMeasures() throws AnalysisException {
		Halstead.Builder builder = Halstead.make(program);

		Logger.msgLogger.debug(this, "###################### START PRGORAM PARSING ######################");

		Listing listing = program.getListing();
		int numInstructions = 0;
		
		InstructionIterator instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			numInstructions++;
			
			{ /* OPERATOR */
				String op = instr.getMnemonicString();
				if (StringUtils.isEmpty(op)) {
					throw new AnalysisException("Empty operator found at addr: '"+instr.getAddressString(false, true)+"'");
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
			
		}
		
		
		Logger.msgLogger.debug(this, "###################### END PRGORAM PARSING ######################");
		
		if (numInstructions == 0) {
			Logger.msgLogger.info(this, "The parsing of the program failed. Maybe the program is not analyzed yet.");

			return null;
		}
		
		return builder.build();
	}

}
