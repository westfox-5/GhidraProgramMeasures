package it.westfox5.ghidra.measure;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;

public abstract class MeasuredProgram {
	/*** -------- IMPLEMENTATIONS -------- */
	public static final AnalysisType<Halstead> HALSTEAD = new AnalysisType<Halstead>() {
		@Override
		public Halstead get(Analyzer analyzer) throws AnalysisException {
			return analyzer.getHalsteadMeasures();
		}

		@Override
		public String display() {
			return "halstead";
		}
	};
	
	
	

	private static final Map<String, AnalysisType<?>> analysisTypesLookup;
	static {
		analysisTypesLookup = new HashMap<>();
		analysisTypesLookup.put(MeasuredProgram.HALSTEAD.display(), MeasuredProgram.HALSTEAD);
	}
	public static AnalysisType<?> getAnalysisTypeByName(String name) {
		return analysisTypesLookup.get(name);
	}
	
	/*** --------------------------------- */
	
	private final Program program;
	private final Map<MeasureKey, Measure<?>> measures;
	private final AnalysisType<? extends MeasuredProgram> analysisType;
	
	protected <T extends MeasuredProgram> MeasuredProgram(AnalysisType<T> analysisType, Program program) {
		this.analysisType = analysisType;
		this.program = program;
		this.measures = new HashMap<>();
	}
	
	public abstract List<Measure<?>> getOrderedMeasures();
	
	public void addMeasure(Measure<?> measure) {
		measures.put(measure.getKey(), measure);
	}

	public Map<MeasureKey, Measure<?>> getMeasures() {
		return measures;
	}

	public Program getProgram() {
		return program;
	}

	public AnalysisType<? extends MeasuredProgram> getAnalysisType() {
		return analysisType;
	}
	
}
