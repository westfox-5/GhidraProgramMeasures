package it.westfox5.ghidra.analyzer;

import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.impl.FunctionAnalyzer;

public class AnalyzerFactory {
	
	public static Analyzer functionAnalyzer(Program program, String functionName) { 
		return new FunctionAnalyzer(program, functionName); 
	}

}
