package args;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import it.westfox5.ghidra.export.Exporter.ExportType;
import it.westfox5.ghidra.measure.AnalysisType;
import it.westfox5.ghidra.measure.MeasuredProgram;
import it.westfox5.ghidra.measure.impl.halstead.Halstead;

public class Argument<V> {
	
	/*
	 	analysis halstead \
	    analyze-function main \
		export json \
		export-path ~ 
	*/
	
	public static abstract class Operator<T> {
		
		public static final Operator<AnalysisType<?>> ANALYSIS_TYPE = new Operator<>(AnalysisType.class, 1, "analysis") {
			@Override
			public AnalysisType<Halstead> getDefaultValue() {
				return MeasuredProgram.HALSTEAD;
			}
		};
		
		public static final Operator<String> ANALYSIS_FUNCTION_NAME = new Operator<>(String.class, 1, "analyze-function"){
			@Override
			public String getDefaultValue() {
				return "main";
			}
		};
		
		public static final Operator<ExportType> EXPORT_TYPE = new Operator<>(ExportType.class, 1, "export") {
			@Override
			public ExportType getDefaultValue() {
				return null; // if default is provided, then the export will be always performed. We don't want this behavior
			}
		};
		
		public static final Operator<String> EXPORT_PATH = new Operator<>(String.class, 1, "export-path") {
			@Override
			public String getDefaultValue() {
				return null;
			}
		};
		
		private final String opCode;
		private final Class<?> opClass;
		private final Integer numArgs;

		private Operator(Class<?> opClass, Integer numArgs, String opCode) {
			this.opCode = opCode;
			this.opClass = opClass;
			this.numArgs = numArgs;
		}

		public Class<?> getOpClass() {
			return opClass;
		}

		public Integer getNumArgs() {
			return numArgs;
		}
		
		public String getOpCode() {
			return opCode;
		}
		
		public abstract T getDefaultValue();


		private static final Map<String, Operator<?>> byOpCode;
		static {
			
			byOpCode = List.of(ANALYSIS_TYPE, ANALYSIS_FUNCTION_NAME, EXPORT_TYPE, EXPORT_PATH).stream()
					.collect(Collectors.toMap(Operator::getOpCode, Function.identity()));
			
			/*
			byOpCode = new HashMap<>(); 
			List.of(ANALYSIS_TYPE, ANALYSIS_FUNCTION_NAME, EXPORT_TYPE, EXPORT_PATH)
				.stream()
				.forEach(
					op -> 
					op.getOpCodes().stream().forEach(
							opCode -> 
							byOpCode.put(opCode, op)));
			*/
		}
		
		public static Operator<?> byOpCode(String opCode) {
			return byOpCode.get(opCode);
		}
	}
	
	private Operator<V> operator;
	private List<V> values;
	
	@SafeVarargs
	public Argument(Operator<V> argOp, V... values) {
		this(argOp, List.of(values));
	}
	
	public Argument(Operator<V> argOp, List<V> values) {
		this.operator = argOp;
		this.values = new ArrayList<>(values);
	}


	public Operator<V> getOperation() {
		return operator;
	}
	public void setOperator(Operator<V> argOp) {
		this.operator = argOp;
	}
	public List<V> getValues() {
		return values;
	}
	public void setValues(List<V> values) {
		this.values = values;
	}
	
	public V getSingleValue() {
		if (operator.getNumArgs() == 1) {
			return values.get(0);
		}
		return null;
	}
}
