package it.westfox5.ghidra.analyzer;

import it.westfox5.ghidra.halstead.Halstead;

public interface Analyzer {
	Halstead getHalsteadMeasures() throws AnalysisException;
	
}
