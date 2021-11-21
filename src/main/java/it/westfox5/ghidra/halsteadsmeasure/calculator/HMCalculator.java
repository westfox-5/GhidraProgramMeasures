package it.westfox5.ghidra.halsteadsmeasure.calculator;

import it.westfox5.ghidra.halsteadsmeasure.HMException;
import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;

public interface HMCalculator {
	HalsteadsMeasure getHalsteadMeasures() throws HMException;
	
}
