package it.westfox5.ghidra.analyzer;

import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;

public abstract class Analyzer {	
	
	protected final Program program;
	
	protected Analyzer(Program program) {
		this.program = program;
	}
	
	public abstract Halstead getHalsteadMeasures() throws AnalysisException;

	public <T extends MeasuredProgram> boolean isAnalysisTypeSupported(AnalysisType<T> analysisType) {
		// TODO generalize this function
		return MeasuredProgram.HALSTEAD == analysisType;
	}
	
	public <T extends MeasuredProgram> T getMeasure(AnalysisType<T> analysisType) throws AnalysisException {
		return analysisType.get(this);
	}
	
}
