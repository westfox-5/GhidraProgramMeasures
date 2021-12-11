package it.westfox5.ghidra.script.args;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.script.args.Argument.Operator;
import it.westfox5.ghidra.util.StringUtils;

public class Parser {
	
	private static final String ARG_VALUE_SEPARATOR = "=";
	
	public static Map<Operator<?>, Argument<?>> parseArgs(String... args) {
		if (!(args!=null && args.length > 0)) {
			return new HashMap<>();
		}
		
		List<Argument<?>> arguments = new ArrayList<>();
		
		List<String> split = List.of(args);
		Iterator<String> tokens = split.iterator();
		while (tokens.hasNext()) {
			String token = tokens.next();
			String[] argValue = token.split(ARG_VALUE_SEPARATOR);
			Operator<?> op = Operator.byOpCode(argValue[0]);
			Argument<?> arg = createArgument(op, argValue[1]);
			
			arguments.add(arg);
		}
			
		return arguments.stream()
			.filter(e -> e != null)
			.collect(Collectors.toMap(e -> e.getOperation(), Function.identity()));
	}

	private static Argument<?> createArgument(Operator<?> op, String value) {
		if (Operator.ANALYSIS_TYPE == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis` argument.");
			}
			if (StringUtils.isEmpty(value)) {
				throw new IllegalArgumentException("Expecting a value for the `analysis` argument but none was provided.");
			}
			
			AnalysisType<?> analysisType = MeasuredProgram.getAnalysisTypeByName(value);
			
			return new Argument<AnalysisType<?>>(Operator.ANALYSIS_TYPE, analysisType);
			
		} else if(Operator.ANALYSIS_FUNCTION_NAME == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis function name` argument.");
			}
			
			if (StringUtils.isEmpty(value)) {
				throw new IllegalArgumentException("Expecting a value for the `analysis function name` argument but none was provided.");
			}
			
			return new Argument<String>(Operator.ANALYSIS_FUNCTION_NAME, value);
		
		} else if(Operator.EXPORT_TYPE == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `export` argument.");
			}
			
			if (StringUtils.isEmpty(value)) {
				throw new IllegalArgumentException("Expecting a value for the `export` argument but none was provided.");
			}
			
			ExportType exportType = ExportType.getExportTypeByName(value);
			
			return new Argument<ExportType>(Operator.EXPORT_TYPE, exportType);
		} else if (Operator.EXPORT_PATH == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `export path` argument.");
			}
			
			if (StringUtils.isEmpty(value)) {
				throw new IllegalArgumentException("Expecting a value for the `export path` argument but none was provided.");
			}
			
			return new Argument<String>(Operator.EXPORT_PATH, value);
		} else {
			throw new RuntimeException("Argument `"+op+"` not implemented.");
		}
	}

}
