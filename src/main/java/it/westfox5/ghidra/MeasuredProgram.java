package it.westfox5.ghidra;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.Measure.MeasureKey;

public abstract class MeasuredProgram {
	
	private final Program program;
	private final Map<MeasureKey, Measure<?>> measures;
	
	protected MeasuredProgram(Program program) {
		this.program = program;
		this.measures = new HashMap<>();
	}
	
	public abstract String getMeasureName();
	
	public void addMeasure(Measure<?> measure) {
		measures.put(measure.getKey(), measure);
	}

	public Map<MeasureKey, Measure<?>> getMeasures() {
		return measures;
	}

	public Program getProgram() {
		return program;
	}

	
}
