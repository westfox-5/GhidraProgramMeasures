package it.westfox5.ghidra.halsteadsmeasure.calculator;

import it.westfox5.ghidra.halsteadsmeasure.HMPlugin;
import it.westfox5.ghidra.halsteadsmeasure.calculator.impl.HMFunctionCalculator;

public class HMCalculatorFactory {
	
	public static HMCalculator functionCalculator(HMPlugin plugin, String functionName) { 
		return new HMFunctionCalculator(plugin, functionName); 
	}

}
