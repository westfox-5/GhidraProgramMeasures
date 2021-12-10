import args.Argument.Operator;

import java.nio.file.Path;

import args.ArgumentsHandler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.util.ProgramHelper;

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

		Function function = ProgramHelper.findFunctionByName(program, args.getOrDefault(Operator.ANALYSIS_FUNCTION_NAME));
		Analyzer analyzer = AnalyzerFactory.functionAnalyzer(program, function);		
		
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
