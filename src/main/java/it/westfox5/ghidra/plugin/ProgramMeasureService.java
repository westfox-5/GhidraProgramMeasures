package it.westfox5.ghidra.plugin;

import java.io.File;

import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;

public class ProgramMeasureService<P extends MeasuredProgram> {
	private final ProgramMeasuresPlugin plugin;
	private final AnalysisType<P> analysisType;
	
	private P cached;
	
	public ProgramMeasureService(ProgramMeasuresPlugin plugin, AnalysisType<P> analysisType) {
		this.plugin = plugin;
		this.analysisType = analysisType;
	}


	public final P getOrCreate() throws AnalysisException {
		if (!has()) {
			create();
		}
		return cached;
	}
	
	public final boolean has() {
		return cached != null;
	}
	
	public final void clear() {
		cached = null;
	}
	
	// TODO: for now only function analysis, and only main function.
	// maybe get function name via the plugin instance?
	private final void create() throws AnalysisException {
		// function calculator

		Program program = plugin.getCurrentProgram();
		String functionName = "main";
		Analyzer calculator = AnalyzerFactory.functionAnalyzer(program, functionName);

		cached = calculator.getMeasure(this.analysisType);
		
	}	


	public File exportAs(ExportType exportType) throws ExportException {
		if (!has()) {
			throw new ExportException("No programs to export.");
		}
		
		Exporter exporter = Exporter.get(exportType);
		return exporter.export(cached);
	}
	
}
