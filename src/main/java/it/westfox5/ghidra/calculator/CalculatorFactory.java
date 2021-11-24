package it.westfox5.ghidra.calculator;

import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.calculator.impl.FunctionCalculator;

public class CalculatorFactory {
	
	public static Calculator functionCalculator(Program program, String functionName) { 
		return new FunctionCalculator(program, functionName); 
	}

}
