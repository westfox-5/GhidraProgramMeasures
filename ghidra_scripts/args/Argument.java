package args;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;

public class Argument<V> {
	
	// analysis-mode=function::function-name=main export-type=json analysis-type=halstead

	public static class Operator<T> {
		
		public static final Operator<String> ANALYSIS_MODE = new Operator<>(String.class, "analysis-mode", "function");
		public static final Operator<String> ANALYSIS_MODE_FUNCTION_NAME = new Operator<>(String.class, "function-name", "main");
		public static final Operator<AnalysisType<?>> ANALYSIS_TYPE = new Operator<>(AnalysisType.class, "analysis-type", MeasuredProgram.HALSTEAD); 	// it.westfox5.ghidra.measure.AnalysisType<T>
		public static final Operator<ExportType> EXPORT_TYPE = new Operator<>(ExportType.class, "export-type", ExportType.JSON);				// it.westfox5.ghidra.export.Exporter.ExportType
		public static final Operator<String> EXPORT_PATH = new Operator<>(String.class, "export-path");
		
		private final String opCode;
		private final Class<?> opClass;
		private final T defaultValue;
		
		private Operator(Class<?> opClass, String opCode) {
			this(opClass,opCode,null);
		}

		private Operator(Class<?> opClass, String opCode, T defaultValue) {
			this.opCode = opCode;
			this.opClass = opClass;
			this.defaultValue = defaultValue;
		}
	
		public String getOpCode() {
			return opCode;
		}
		
		public Class<?> getOpClass() {
			return opClass;
		}

		public T getDefaultValue() {
			return defaultValue;
		}



		private static final Map<String, Operator<?>> byOpCode;
		static {
			byOpCode = List.of(ANALYSIS_MODE, ANALYSIS_MODE_FUNCTION_NAME, ANALYSIS_TYPE, EXPORT_TYPE, EXPORT_PATH).stream()
					.collect(Collectors.toMap(Operator::getOpCode, Function.identity()));
		}
		
		public static Operator<?> byOpCode(String opCode) {
			return byOpCode.get(opCode);
		}

		@Override
		public String toString() {
			return "Operator [`" + opCode + "`]";
		}
		
		
	}
	
	private Operator<V> operator;
	private V value;
	
	private Argument<?> containerArgRef;
	
	public Argument(Operator<V> argOp, V value) {
		this.operator = argOp;
		this.value = value;
	}
	
	private Argument(Operator<V> argOp, V value, Argument<?> containerArgRef) {
		this(argOp, value);
		this.containerArgRef = containerArgRef;
	}

	
	public Operator<V> getOperation() {
		return operator;
	}
	public void setOperator(Operator<V> argOp) {
		this.operator = argOp;
	}
	public V getValue() {
		return value;
	}
	public void setValue(V value) {
		this.value = value;
	}
	
	public Argument<?> getContainerArgumemt() {
		return containerArgRef;
	}


	public static class MultiArgument<V> extends Argument<V> {

		private Map<Operator<?>, Argument<?>> subArgs; // must be of same type as principal
		
		public MultiArgument(Operator<V> argOp, V value) {
			super(argOp, value);
		}
		
		public <T> void addArg(Operator<T> argOp, T value) {
			if (subArgs == null) {
				subArgs = new HashMap<>();
			}
			Argument<T> subArg = new Argument<>(argOp, value, this);
			subArgs.put(argOp, subArg);
		}

		public Map<Operator<?>, Argument<?>> getSubArgs() {
			return subArgs;
		}

		
		
	}
}
