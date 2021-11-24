package it.westfox5.ghidra.export.impl;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;

import it.westfox5.ghidra.Measure;
import it.westfox5.ghidra.Measure.MeasureKey;
import it.westfox5.ghidra.MeasuredProgram;
import it.westfox5.ghidra.export.Exporter;
import it.westfox5.ghidra.export.FileExtension;
import it.westfox5.ghidra.util.Formatter;
import it.westfox5.ghidra.util.logger.Logger;

/**
 * JSON implementation of the HMExporter.
 * 
 * File structure:
 * {
 * 	programs: [
 * 		{
 * 			name: String
 * 			analysis: {
 * 				halstead: {
 * 					dump of halsteads
 * 				},
 * 				-- future measures here --
 * 			}
 * 		},
 * 		...
 * 	]
 * }
 */
public class JSONExporter extends Exporter {
	
	public JSONExporter(String filename) {
		super(filename, FileExtension.JSON);
	}

	@Override
	public String getFileContent(MeasuredProgram mp) {		
		Formatter formatter = new Formatter();
		
		formatter.write("{");
		formatter.indent().write(quotate("programs")+": [");
		formatter.indent().write("{");
		// for now just one program per execution..
		formatter.indent().write(quotate("name") + ": "+quotate(mp.getProgram().getName())+",");
		formatter.write(quotate("analysis") + ": [");
		formatter.indent().write("{");

		Map<MeasureKey, Measure<?>> measures = mp.getMeasures();
		formatter.indent().write(quotate(mp.getMeasureName()) + ": {");
		formatter.indent();
		for (MeasureKey key: measures.keySet()) {
			Measure<?> measure = measures.get(key);
			formatter.write(quotate(key.getName()) + ": " + quotate(measure.getValue()) + ", ");
		}
		formatter.outdent().write("},");
		formatter.outdent().write("],");

		formatter.outdent().write("},");
		formatter.outdent().write("},");
		formatter.outdent().write("],");
		formatter.outdent().write("}") ;
		
		String content = formatter.get();
		if (!formatter.validateIndentation()) {
			Logger.msgLogger.err(this, "Invalid format. Missing "+formatter.getIndentationLevel()+" levels of indentation to close the formatter.\nCurrent string is:\n"+content);
			return null;
		}
		return content;
	}

	private String quotate(Object s) {
		if (s instanceof BigDecimal) {
			BigDecimal bd = (BigDecimal)s;
			return quotate(bd.setScale(3, RoundingMode.HALF_UP).toPlainString());
		}
		return "\""+s+"\"";
	}
}
