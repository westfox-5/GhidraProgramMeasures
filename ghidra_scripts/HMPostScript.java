import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.calculator.CalculationException;
import it.westfox5.ghidra.calculator.Calculator;
import it.westfox5.ghidra.calculator.CalculatorFactory;
import it.westfox5.ghidra.export.ExportException;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.ExporterFactory;
import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;
import it.westfox5.ghidra.util.logger.Logger;

public class HMPostScript extends GhidraScript {

	public HalsteadsMeasure calculateForMainFunction() throws CalculationException {
		
		// function calculator
		String functionName = "main";
		Program program = getCurrentProgram();
		Calculator calculator = CalculatorFactory.functionCalculator(program, functionName);

		HalsteadsMeasure hm = calculator.getHalsteadMeasures();
		if (hm == null) throw new CalculationException("Cannot calculate Halstead's Measures for function `"+functionName+"`");
		return hm;
	}
	
	public File exportToJSONFile(HalsteadsMeasure hm) throws ExportException {
		String filename = "halsteads_measure_headless";
		Exporter exporter = ExporterFactory.jsonExporter(filename);
		return exporter.export(hm);
	}
	
	@Override
	protected void run() throws Exception {
		System.out.println("Post-Script!");
		
		HalsteadsMeasure hm = calculateForMainFunction();
		
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
