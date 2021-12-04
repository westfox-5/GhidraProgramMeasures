package args;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import args.Argument.MultiArgument;
import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.util.StringUtils;

public class Parser {
	private static final String ARG_SEPARATOR = "=";
	private static final String SUBARG_MAIN_SEPARATOR = "::";
	private static final String SUBARG_INNER_SEPARATOR = ";";

	
	public static Map<ArgOperation, Argument<?>> parseArgs(String... args) {
		return List.of(args).stream()
			.map(e -> parseArg(e))
			.filter(e -> e != null)
			.collect(Collectors.toMap(e -> e.getArgOperation(), Function.identity()));
	}
	
	private static Argument<?> parseArg(String arg) {
		if (StringUtils.isEmpty(arg)) return null;
				
		String[] split = arg.split(ARG_SEPARATOR);
		if (split.length > 1) {
			ArgOperation op = ArgOperation.byOpCode(split[0]);
			String value = split[1];
			
			return createArgument(op, value);
		}
		
		return null;
	}
	
	private static Argument<?> createArgument(ArgOperation arg, String value) {
		switch(arg) {
		case ANALYSIS_MODE:
			MultiArgument<String> analysisModeArg = new MultiArgument<>(arg, value);
			
			List<String> analysisModeSubArgs = new ArrayList<>(List.of(value.split(SUBARG_MAIN_SEPARATOR)));
			if (analysisModeSubArgs.size() < 2)
				throw new RuntimeException("Expecting sub-arguments for argument `"+arg.name()+"` but found none.");
			
			// main_arg=main_arg_value::sub_arg1=sub_arg_value1;sub_arg2=sub_arg_value2...
			
			analysisModeSubArgs = analysisModeSubArgs.subList(1, analysisModeSubArgs.size()); // remove main_arg
			analysisModeSubArgs.stream().map(s -> s.split(SUBARG_INNER_SEPARATOR)).collect(Collectors.toList());
			parseSubArgs(analysisModeArg, analysisModeSubArgs);
			
			return analysisModeArg;
			
		case ANALYSIS_TYPE:
			AnalysisType<?> analysisType = MeasuredProgram.getAnalysisTypeByName(value);
			if (analysisType == null)
				throw new RuntimeException("No analysis type found for name `"+value+"`.");

			return new Argument<AnalysisType<?>>(arg, analysisType);
		
		case EXPORT_TYPE:
			ExportType exportType = ExportType.getExportTypeByName(value);
			if (exportType == null)
				throw new RuntimeException("No export type found for name `"+value+"` but found none.");

			MultiArgument<ExportType> exportTypeArg = new MultiArgument<>(arg, exportType);
			
			List<String> exportTypeSubArg = new ArrayList<>(List.of(value.split(SUBARG_MAIN_SEPARATOR)));
			if (exportTypeSubArg.size() < 2)
				return exportTypeArg;
				//throw new RuntimeException("Expecting sub-arguments for argument `"+arg.name()+"` but found none.");
			
			// main_arg=main_arg_value::sub_arg1=sub_arg_value1;sub_arg2=sub_arg_value2...
			
			exportTypeSubArg = exportTypeSubArg.subList(1, exportTypeSubArg.size()); // remove main_arg
			exportTypeSubArg.stream().map(s -> s.split(SUBARG_INNER_SEPARATOR)).collect(Collectors.toList());
			parseSubArgs(exportTypeArg, exportTypeSubArg);
			
			return exportTypeArg;

		default:
			throw new RuntimeException("Argument `"+arg.name()+"` not implemented.");
		}
	}

	private static void parseSubArgs(MultiArgument<?> mainArg, List<String> subArgs) {
		for (String arg: subArgs) {
			if (StringUtils.isEmpty(arg)) continue;
						
			String[] split = arg.split(ARG_SEPARATOR);
			if (split.length > 1) {
				ArgOperation op = ArgOperation.byOpCode(split[0]);
				Object value = split[1];
				
				mainArg.addArg(op, value);
			}
			
		}
	}
}
