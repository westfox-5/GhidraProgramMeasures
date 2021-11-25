package it.westfox5.ghidra.export;

import it.westfox5.ghidra.MeasuredProgram;
import it.westfox5.ghidra.export.impl.JSONExporter;

public class ExporterFactory {
	public static Exporter jsonExporter(MeasuredProgram... programs) { 
		return new JSONExporter(programs);
	}
}
