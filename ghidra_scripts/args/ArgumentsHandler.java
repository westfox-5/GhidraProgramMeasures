package args;

import java.util.List;
import java.util.Map;

public class ArgumentsHandler {
	public Map<Argument.Operator<?>, Argument<?>> args;
	
	public ArgumentsHandler(String... argStr) {
		init(argStr);
	}
	
	private void init(String... argStr) {
		if (argStr != null && argStr.length > 0) {
			this.args = Parser.parseArgs(argStr);
		}
	}

	@SuppressWarnings("unchecked")
	public <T> Argument<T> getArgument(Argument.Operator<T> operator)  {
		return has(operator) ? (Argument<T>)args.get(operator) : null;
	}
	
	public <T> T get(Argument.Operator<T> operator)  {
		return has(operator) ? getArgument(operator).getSingleValue() : null;
	}
	
	public <T> T getOrDefault(Argument.Operator<T> operator) {
		if (has(operator)) {
			Argument<T> argument = getArgument(operator);
			T value = argument.getSingleValue();
			if (value != null) {
				return value;
			}
		}
		
		return operator.getDefaultValue();
	}
	
	public <T> List<T> getMultipleValues(Argument.Operator<T> operator) {
		return has(operator) ? getArgument(operator).getValues() : null;

	}
	
	@SuppressWarnings("unchecked")
	public <T> boolean has(Argument.Operator<T> operator) {
		Argument<T> argument = (Argument<T>)args.get(operator);
		if (argument == null) return false;
		
		if (argument.getValues() != null) return true;
		
		if (operator.getDefaultValue() != null) return true;
		
		return false;
	}
}
