package it.westfox5.ghidra.halsteadsmeasure.export.impl;

import java.math.BigDecimal;
import java.math.RoundingMode;

import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;
import it.westfox5.ghidra.halsteadsmeasure.export.FileExtension;
import it.westfox5.ghidra.halsteadsmeasure.export.HMExporter;
import it.westfox5.ghidra.halsteadsmeasure.util.StringUtils;

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
public class HMJSONExporter extends HMExporter {
	
	public HMJSONExporter(String filename) {
		super(filename, FileExtension.JSON);
	}

	@Override
	public StringBuilder getFileContent(HalsteadsMeasure hm) {
		StringBuilder sb = new StringBuilder();
		
		// TODO create `Indentator` class! add checks of correct indentation!
		appendIndentation(sb, 0).append("{")			.append("\n");
		appendIndentation(sb, 1).append(quotate("programs")+": [").append("\n");
		appendIndentation(sb, 2).append("{").append("\n");
		// for now just one program per execution..
		appendIndentation(sb, 3).append("\"name\": \""+hm.getProgramName()+"\",").append("\n");
		appendIndentation(sb, 3).append("\"analysis\": {").append("\n");

		// TODO loop measures? maybe the `Program` interface can provide a `List<Measure>` obj. a `Measure` should have name, value, description..
		appendIndentation(sb, 4).append(quotate("n1")+":"+quotate(hm.getNumDistinctOperators())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("n2")+":"+quotate(hm.getNumDistinctOperands())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("N1")+":"+quotate(hm.getNumOperators())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("N2")+":"+quotate(hm.getNumOperands())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("vocabulary")+":"+quotate(hm.getVocabulary())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("length")+":"+quotate(hm.getLength())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("estimatedLength")+":"+quotate(hm.getEstimatedLength())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("volume")+":"+quotate(hm.getVolume())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("difficulty")+":"+quotate(hm.getDifficulty())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("effort")+":"+quotate(hm.getEffort())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("codingTime")+":"+quotate(hm.getCodingTime())+",").append("\n");
		appendIndentation(sb, 4).append(quotate("estimatedErrors")+":"+quotate(hm.getEstimatedErrors())+",").append("\n");
		

		appendIndentation(sb, 3).append("},").append("\n");
		appendIndentation(sb, 2).append("},").append("\n");
		appendIndentation(sb, 1).append("],").append("\n");
		appendIndentation(sb, 0).append("}") .append("\n");
		
		return sb;
	}
	
	
	private StringBuilder appendIndentation(StringBuilder sb, int indentationLevel) {
		sb.append(StringUtils.repeat(" ", indentationLevel));
		return sb;
	}
	
	private String quotate(BigDecimal bd) {
		return quotate(bd.setScale(2, RoundingMode.HALF_UP).toPlainString());
	}
	private String quotate(String s) {
		return "\""+s+"\"";
	}
}
