import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Set;

import args.ArgOperation;
import args.Argument;
import args.Parser;
import args.Argument.MultiArgument;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;
import it.westfox5.ghidra.util.logger.Logger;

public class ProgramMeasuresPostScript extends GhidraScript {
	
	public Halstead calculateForMainFunction() throws AnalysisException {
		
		// function calculator
		String functionName = "main";
		Program program = getCurrentProgram();
		Analyzer calculator = AnalyzerFactory.functionAnalyzer(program, functionName);
		
		Halstead measuredProgram = calculator.getMeasure(MeasuredProgram.HALSTEAD);
		if (measuredProgram == null) throw new AnalysisException("Cannot calculate Halstead's Measures for function `"+functionName+"`");
		return measuredProgram;
	}
	
	public File exportToJSONFile(Halstead hm) throws ExportException {
		Exporter exporter = Exporter.get(ExportType.JSON);
		return exporter.export(hm);
	}
	
	@Override
	protected void run() throws Exception {
		System.out.println("Post-Script!");
		
		Map<ArgOperation, Argument<?>> arguments = null;
		
		String[] scriptArgs = getScriptArgs();
		if (scriptArgs != null && scriptArgs.length>0) {
			System.out.println("Parsing args: "+ scriptArgs);

			arguments = Parser.parseArgs(scriptArgs);
		}
		
		process(arguments);
		
		/*
		Halstead hm = calculateForMainFunction();
		
		// TODO find a way to create dialogs (@see Msg.showInfo)
		Logger.msgLogger.info(this,
		"\n" + 	"---- Halstead's Measures ----------------------------"   + "\n" +
				" Unique operators (n1):\t"+ hm.getNumDistinctOperators() + "\n" +//: \n" + uniqueOpStr);
				" Unique operands  (n2):\t"+ hm.getNumDistinctOperands()  + "\n" +//: \n" + uniqueOpndStr);
				" Total operators  (N1):\t"+ hm.getNumOperators()         + "\n" +
				" Total operands   (N2):\t"+ hm.getNumOperands()          + "\n" +
				"-----------------------------------------------------"   + "\n" // put "(HMPlugin)" in new line
			);
		
		exportToJSONFile(hm);
		*/
	}
	
	@SuppressWarnings("unchecked")
	// TODO migliora sta roba
	private void process(Map<ArgOperation, Argument<?>> args) throws AnalysisException, ExportException {
		Argument<String> analysisModeArg = (Argument<String>) args.get(ArgOperation.ANALYSIS_MODE); // TODO add default
		Argument<String> analysisModeFunctionNameArg = analysisModeArg != null ? (Argument<String>) ((MultiArgument<?>)analysisModeArg).getSubArgs().get(ArgOperation.ANALYSIS_MODE_FUNCTION_NAME) : null;
		
		Argument<AnalysisType<?>> analysisTypeArg = (Argument<AnalysisType<?>>) args.get(ArgOperation.ANALYSIS_TYPE);	// TODO add default

		Argument<ExportType> exportTypeArg = (Argument<ExportType>) args.get(ArgOperation.EXPORT_TYPE); // TODO maybe no default here
		Argument<String> exportPathArg = exportTypeArg != null? (Argument<String>) ((MultiArgument<?>)exportTypeArg).getSubArgs().get(ArgOperation.EXPORT_PATH) : null; // TODO maybe no default here

		/*------------------ ANALYSIS ------------------*/
		
		MeasuredProgram measuredProgram = null;
		
		Program program = getCurrentProgram();
		if ("function".equals(analysisModeArg.getValue())) {
			Analyzer analyzer = AnalyzerFactory.functionAnalyzer(program, analysisModeFunctionNameArg.getValue());
			
			measuredProgram = analyzer.getMeasure(analysisTypeArg.getValue());
		}
		
		if (measuredProgram == null) {
			throw new AnalysisException("Cannot analyze program!");
		}
		
		/*------------------  EXPORT ------------------*/
		
		if (exportTypeArg != null) {
			Exporter exporter = Exporter.get(exportTypeArg.getValue());
			
			if (exportPathArg != null) {
				exporter.export(exportPathArg.getValue(), measuredProgram);
			} else {
				exporter.export(measuredProgram);
			}
			
		}
		
	}
	

}
