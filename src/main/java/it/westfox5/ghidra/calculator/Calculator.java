package it.westfox5.ghidra.calculator;

import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;

public interface Calculator {
	HalsteadsMeasure getHalsteadMeasures() throws CalculationException;
	
}
