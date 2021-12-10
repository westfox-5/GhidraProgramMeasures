package it.westfox5.ghidra.analyzer;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.impl.FunctionAnalyzer;

public class AnalyzerFactory {
	
	public static Analyzer functionAnalyzer(Program program, Function function) { 
		return new FunctionAnalyzer(program, function); 
	}

}
