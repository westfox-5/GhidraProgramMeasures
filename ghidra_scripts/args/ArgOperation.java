package args;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum ArgOperation {
	// analysis-mode=function::function-name=main export-type=json analysis-type=halstead
	ANALYSIS_MODE("analysis-mode"), // 'analysis-mode=function::function-name=main' only for now
	ANALYSIS_MODE_FUNCTION_NAME("function-name"),
	ANALYSIS_TYPE("analysis-type"), // it.westfox5.ghidra.measure.AnalysisType<T>
	EXPORT_TYPE("export-type"),		// it.westfox5.ghidra.export.Exporter.ExportType
	EXPORT_PATH("export-path");		// String
	
	private final String opCode;
	private ArgOperation(String opCode) {
		this.opCode = opCode;
	}

	public String getOpCode() {
		return opCode;
	}
	
	private static final Map<String, ArgOperation> byOpCode;
	static {
		byOpCode = List.of(ArgOperation.values()).stream().collect(Collectors.toMap(ArgOperation::getOpCode, Function.identity()));
	}
	
	public static ArgOperation byOpCode(String opCode) {
		return byOpCode.get(opCode);
	}
	
}
