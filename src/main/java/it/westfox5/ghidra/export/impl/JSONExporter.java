package it.westfox5.ghidra.export.impl;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Iterator;
import java.util.List;

import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.measure.Measure;
import it.westfox5.ghidra.measure.MeasureKey;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.util.Formatter;
import it.westfox5.ghidra.util.logger.Logger;

/**
 * JSON implementation of the HMExporter.
 * 
 * File structure:
 * ```
 * {
 * 	programs: [
 * 		{
 * 			name: String
 * 			analysis: {
 *	 			halstead: {
 *	 				-- halstead's measures here --
 *	 			},
 *				{
 * 					-- future measures here --
 * 				}
 * 			}
 * 		},
 * 		-- other analyzed programs here --
 * 	]
 * }
 * ```
 */
public class JSONExporter extends Exporter {
	
	public JSONExporter() {
		super(ExportType.JSON);
	}

	@Override
	public String getFileContent(List<MeasuredProgram> programs) {		
		Formatter formatter = new Formatter();
		
		// --- START ----
		formatter.write("{");
		
		// -- Start `programs` ----
		formatter.indent().write(quotate("programs")+": [");

		Iterator<MeasuredProgram> programsIter = programs.iterator();
		while(programsIter.hasNext()) {
			MeasuredProgram measuredProgram = programsIter.next();
			
			// --- Start program ----
			formatter.indent().write("{");
			formatter.indent().write(quotate("name") + ": "+quotate(measuredProgram.getProgram().getName())+",");
			
			// --- Start `analysis` ----
			formatter.write(quotate("analysis") + ": {");
		
			// --- Start measures ----
			formatter.indent().write(quotate(measuredProgram.getAnalysisType().display()) + ": {");
			dumpMeasures(measuredProgram, formatter);
				
			formatter.outdent().write("},");
			// --- End measures ----
			
			formatter.outdent().write("},");
			// --- End `analysis` ----
			
			formatter.outdent().write("},");
			// --- End program ----

		}
		
		formatter.outdent().write("],");
		// --- End `programs` ----
		
		formatter.outdent().write("}") ;
		// --- END ----
		
		String content = formatter.get();
		if (!formatter.validateIndentation()) {
			Logger.msgLogger.err(this, "Invalid format. Missing "+formatter.getIndentationLevel()+" levels of indentation to close the formatter.\nCurrent string is:\n"+content);
			return null;
		}
		return content;
	}

	@Override
	public void dumpMeasures(MeasuredProgram program, Formatter formatter) {
		List<Measure<?>> orderedMeasures = program.getOrderedMeasures();
		formatter.indent();

		for (Measure<?> measure: orderedMeasures) {
			MeasureKey key = measure.getKey();
			formatter.write(quotate(key.getName()) + ": {");
			formatter.indent();
			formatter.write(quotate("name") + ": " + quotate(key.getName()) + ",");
			formatter.write(quotate("value") + ": " + quotate(measure.getValue()) + ",");
			for(String additionalKey: key.getAdditionalKeys()) {
				formatter.write(quotate(additionalKey) + ": " + quotate(key.getAdditionalValue(additionalKey)) + ",");
	
			}
			formatter.outdent().write("},");
		}
	}


	private String quotate(Object s) {
		if (s instanceof BigDecimal) {
			BigDecimal bd = (BigDecimal)s;
			return bd.setScale(3, RoundingMode.HALF_UP).toPlainString();
		}
		return "\""+s+"\"";
	}

}
