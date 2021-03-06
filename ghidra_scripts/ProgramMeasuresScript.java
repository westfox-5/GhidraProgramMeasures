
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.script.args.ArgumentsHandler;
import it.westfox5.ghidra.script.args.Argument.Operator;
import it.westfox5.ghidra.util.ProgramHelper;

/*
	The ProgramMeasuresPlugin must be installed in Ghidra in order to use this script.
	Please follow installation instructions in the README file.
*/
public class ProgramMeasuresScript extends GhidraScript {
	
	@Override
	protected void run() throws Exception {
		ArgumentsHandler argsHandler = new ArgumentsHandler(getScriptArgs());
		
		process(argsHandler);
	}
	
	
	private void process(ArgumentsHandler args) throws AnalysisException, ExportException {
		MeasuredProgram measuredProgram = null;		
		Program program = getCurrentProgram();

		/*-----------------  ANALYSIS -----------------*/
		Analyzer analyzer;
		if (args.has(Operator.ANALYSIS_PROGRAM)) {
			analyzer = AnalyzerFactory.programAnalyzer(program);
		
		} else if (args.has(Operator.ANALYSIS_FUNCTION_NAME)) {
			Function function = ProgramHelper.findFunctionByName(program, args.getOrDefault(Operator.ANALYSIS_FUNCTION_NAME));
			analyzer = AnalyzerFactory.functionAnalyzer(program, function);		
			
		} else {
			throw new IllegalArgumentException("Please provide the type of analysis to perform.");
		}
		
		measuredProgram = analyzer.getMeasure(args.getOrDefault(Operator.ANALYSIS_TYPE));
		if (measuredProgram == null) {
			throw new AnalysisException("Could not analyze the program.");
		}
		
		/*------------------  EXPORT ------------------*/
		
		if (args.has(Operator.EXPORT_TYPE)) {
			Exporter exporter = Exporter.get(args.get(Operator.EXPORT_TYPE));
			
			if (args.has(Operator.EXPORT_PATH)) {
				Path destPath = Path.of(args.get(Operator.EXPORT_PATH));
				exporter.export(destPath, measuredProgram);
			} else {
				exporter.export(measuredProgram);
			}
			
		}
		
	}
	

}
