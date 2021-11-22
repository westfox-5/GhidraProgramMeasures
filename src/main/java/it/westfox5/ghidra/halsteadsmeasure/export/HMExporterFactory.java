package it.westfox5.ghidra.halsteadsmeasure.export;

import it.westfox5.ghidra.halsteadsmeasure.export.impl.HMJSONExporter;

public class HMExporterFactory {
	public static HMExporter jsonExporter(String exportFilename) { 
		return new HMJSONExporter(exportFilename);
	}
}
