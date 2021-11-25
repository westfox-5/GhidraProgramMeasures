import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;
import it.westfox5.ghidra.analyzer.Analyzer;
import it.westfox5.ghidra.analyzer.AnalyzerFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.ExporterFactory;
import it.westfox5.ghidra.halstead.Halstead;
import it.westfox5.ghidra.util.logger.Logger;

public class HMPostScript extends GhidraScript {

	public Halstead calculateForMainFunction() throws AnalysisException {
		
		// function calculator
		String functionName = "main";
		Program program = getCurrentProgram();
		Analyzer calculator = AnalyzerFactory.functionCalculator(program, functionName);

		Halstead hm = calculator.getHalsteadMeasures();
		if (hm == null) throw new AnalysisException("Cannot calculate Halstead's Measures for function `"+functionName+"`");
		return hm;
	}
	
	public File exportToJSONFile(Halstead hm) throws ExportException {
		Exporter exporter = ExporterFactory.jsonExporter(hm);
		return exporter.export();
	}
	
	@Override
	protected void run() throws Exception {
		System.out.println("Post-Script!");
		
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
	}

}
