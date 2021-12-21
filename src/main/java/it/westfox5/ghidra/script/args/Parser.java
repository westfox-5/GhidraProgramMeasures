package it.westfox5.ghidra.script.args;

import java.util.ArrayList;
import java.util.Arrays;
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
			List<String> argValues = new ArrayList<String>(Arrays.asList(token.split(ARG_VALUE_SEPARATOR)));
			Operator<?> op = Operator.byOpCode(argValues.remove(0));
			Argument<?> arg = createArgument(op, argValues);
			
			arguments.add(arg);
		}
			
		return arguments.stream()
			.filter(e -> e != null)
			.collect(Collectors.toMap(e -> e.getOperation(), Function.identity()));
	}

	private static Argument<?> createArgument(Operator<?> op, List<String> argValues) {
		int numValuesProvided = argValues.size();
		if (Operator.ANALYSIS_TYPE == op) {
			if (numValuesProvided != op.getNumArgs()) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis` argument but "+argValues.size()+" was provided.");
			}
			
			AnalysisType<?> analysisType = MeasuredProgram.getAnalysisTypeByName(argValues.get(0));
			
			return new Argument<AnalysisType<?>>(Operator.ANALYSIS_TYPE, analysisType);
			
		} else if(Operator.ANALYSIS_FUNCTION_NAME == op) {
			if (numValuesProvided != op.getNumArgs()) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis function name` argument but "+argValues.size()+" was provided.");
			}
			
			return new Argument<String>(Operator.ANALYSIS_FUNCTION_NAME, argValues);
		
		} else if(Operator.ANALYSIS_PROGRAM == op) {
			if (numValuesProvided != op.getNumArgs()) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis program` argument but "+argValues.size()+" was provided.");
			}
			
			return new Argument<String>(Operator.ANALYSIS_PROGRAM);
		
		} else if(Operator.EXPORT_TYPE == op) {
			if (numValuesProvided != op.getNumArgs()) {
				throw new IllegalArgumentException("Expecting only 1 value for the `export` argument but "+argValues.size()+" was provided.");
			}
			
			ExportType exportType = ExportType.getExportTypeByName(argValues.get(0));
			
			return new Argument<ExportType>(Operator.EXPORT_TYPE, exportType);
		} else if (Operator.EXPORT_PATH == op) {
			if (numValuesProvided != op.getNumArgs()) {
				throw new IllegalArgumentException("Expecting only 1 value for the `export path` argument but "+argValues.size()+" was provided.");
			}
			
			return new Argument<String>(Operator.EXPORT_PATH, argValues);
		} else {
			throw new RuntimeException("Argument `"+op+"` not implemented.");
		}
	}

}
