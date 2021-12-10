package it.westfox5.ghidra.util;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.analyzer.AnalysisException;

public class ProgramHelper {
	public static Function findFunctionByName(Program p, String functionName) throws AnalysisException {
		if (StringUtils.isEmpty(functionName)) {
			throw new AnalysisException("No function name provided");
		}
		
		if (p == null) {
			throw new AnalysisException("No program provided");
		}
		
		List<Function> fns = p.getListing().getGlobalFunctions(functionName);
		if (!(fns != null && !fns.isEmpty())) {
			throw new AnalysisException("No function found in current program with name `"+functionName+"`.");
		}
		if (fns.size() > 1) {
			throw new AnalysisException("More than 1 function found in current program with name `"+functionName+"`.");
		}
		
		// fns.size() == 1
		return fns.iterator().next();
	}
	
}
