package it.westfox5.ghidra.export;

import it.westfox5.ghidra.export.impl.JSONExporter;

public class ExporterFactory {
	public static Exporter jsonExporter(String exportFilename) { 
		return new JSONExporter(exportFilename);
	}
}
