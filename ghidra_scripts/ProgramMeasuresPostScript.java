import args.Argument.Operator;
import args.ArgumentsHandler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.measure.MeasuredProgram;

public class ProgramMeasuresPostScript extends GhidraScript {
	
	@Override
	protected void run() throws Exception {
		System.out.println("Post-Script!");
		
		ArgumentsHandler argsHandler = new ArgumentsHandler(getScriptArgs());
		
		process(argsHandler);
	}
	
	
	private void process(ArgumentsHandler argsHandler) throws AnalysisException, ExportException {
		MeasuredProgram measuredProgram = null;
		
		Program program = getCurrentProgram();
		if ("function".equals(argsHandler.getOrDefault(Operator.ANALYSIS_MODE))) {
			Analyzer analyzer = AnalyzerFactory.functionAnalyzer(program, argsHandler.getOrDefault(Operator.ANALYSIS_MODE_FUNCTION_NAME));
			
			measuredProgram = analyzer.getMeasure(argsHandler.getOrDefault(Operator.ANALYSIS_TYPE));
		}
		
		if (measuredProgram == null) {
			throw new AnalysisException("Could not analyze the program.");
		}
		
		/*------------------  EXPORT ------------------*/
		
		if (argsHandler.has(Operator.EXPORT_TYPE)) {
			Exporter exporter = Exporter.get(argsHandler.get(Operator.EXPORT_TYPE));
			
			if (argsHandler.has(Operator.EXPORT_PATH)) {
				exporter.export(argsHandler.get(Operator.EXPORT_PATH), measuredProgram);
			} else {
				exporter.export(measuredProgram);
			}
			
		}
		
	}
	

}
