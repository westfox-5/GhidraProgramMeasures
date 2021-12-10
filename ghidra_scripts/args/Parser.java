package args;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import args.Argument.Operator;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;

public class Parser {
	
	public static Map<Operator<?>, Argument<?>> parseArgs(String... args) {
		if (!(args!=null && args.length > 0)) {
			return new HashMap<>();
		}
		
		
		List<Argument<?>> arguments = new ArrayList<>();
		
		List<String> split = List.of(args);
		Iterator<String> tokens = split.iterator();
		while (tokens.hasNext()) {
			String token = tokens.next();
			Operator<?> op = Operator.byOpCode(token);
			Argument<?> arg = createArgument(op, tokens);
			
			arguments.add(arg);
		}
			
		return arguments.stream()
			.filter(e -> e != null)
			.collect(Collectors.toMap(e -> e.getOperation(), Function.identity()));
	}

	private static Argument<?> createArgument(Operator<?> op, Iterator<String> tokens) {
		if (Operator.ANALYSIS_TYPE == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis` argument.");
			}
			if (!tokens.hasNext()) {
				throw new IllegalArgumentException("Expecting 1 value for the `analysis` argument but none was provided.");
			}
			
			String analysisTypeName = tokens.next();
			AnalysisType<?> analysisType = MeasuredProgram.getAnalysisTypeByName(analysisTypeName);
			
			return new Argument<AnalysisType<?>>(Operator.ANALYSIS_TYPE, analysisType);
			
		} else if(Operator.ANALYSIS_FUNCTION_NAME == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `analysis function name` argument.");
			}
			
			if (!tokens.hasNext()) {
				throw new IllegalArgumentException("Expecting 1 value for the `analysis function name` argument but none was provided.");
			}
			
			String analysisFunctionName = tokens.next();
			
			return new Argument<String>(Operator.ANALYSIS_FUNCTION_NAME, analysisFunctionName);
		
		} else if(Operator.EXPORT_TYPE == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `export` argument.");
			}
			
			if (!tokens.hasNext()) {
				throw new IllegalArgumentException("Expecting 1 value for the `export` argument but none was provided.");
			}
			
			String exportTypeName = tokens.next();
			ExportType exportType = ExportType.getExportTypeByName(exportTypeName);
			
			return new Argument<ExportType>(Operator.EXPORT_TYPE, exportType);
		} else if (Operator.EXPORT_PATH == op) {
			if (op.getNumArgs() != 1) {
				throw new IllegalArgumentException("Expecting only 1 value for the `export path` argument.");
			}
			
			if (!tokens.hasNext()) {
				throw new IllegalArgumentException("Expecting 1 value for the `export path` argument but none was provided.");
			}
			
			String exportPath = tokens.next();
			
			return new Argument<String>(Operator.EXPORT_PATH, exportPath);
		

		} else {
			throw new RuntimeException("Argument `"+op+"` not implemented.");
		}
	}

}
