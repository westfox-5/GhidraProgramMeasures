package it.westfox5.ghidra.plugin;

import java.io.File;
import java.nio.file.Path;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.util.ProgramHelper;

public class ProgramMeasureService<P extends MeasuredProgram> {
	private final ProgramMeasuresPlugin plugin;
	private final AnalysisType<P> analysisType;
	
	private Program program;
	private Function function;
	private P cached;
	
	public ProgramMeasureService(ProgramMeasuresPlugin plugin, AnalysisType<P> analysisType) {
		this.plugin = plugin;
		this.analysisType = analysisType;
	}

	public final void updateLoc(Program p, Function f) {
		this.program = p;
		this.function = f;
		reinitialize();
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
	
	public final void reinitialize() {
		cached = null;
	}
	
	private final void create() throws AnalysisException {
		// function calculator

		if (program == null)
			program = plugin.getCurrentProgram();
		
		if (function == null) {
			function = ProgramHelper.findFunctionByName(program, "main");
			if (function == null) {
				throw new AnalysisException("Default function `main` not found in the program!");
			}
		}
		
		Analyzer calculator = AnalyzerFactory.functionAnalyzer(program, function);
		
		cached = calculator.getMeasure(this.analysisType);
	}	
	
	public final Function getFunction() {
		return this.function;
	}
	
	public File exportAs(Path destPath, ExportType exportType) throws ExportException {
		if (!has()) {
			throw new ExportException("No programs to export.");
		}
		
		Exporter exporter = Exporter.get(exportType);
		return exporter.export(destPath, cached);
	}
	
}
