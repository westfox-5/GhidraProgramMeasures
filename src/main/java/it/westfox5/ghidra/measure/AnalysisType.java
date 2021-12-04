package it.westfox5.ghidra.measure;

import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;

public interface AnalysisType<T extends MeasuredProgram> {
	public T get(Analyzer analyzer) throws AnalysisException;
	public String display();
	
}
