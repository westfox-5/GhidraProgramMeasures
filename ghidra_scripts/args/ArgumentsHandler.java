package args;

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
		return has(operator) ? getArgument(operator).getValue() : null;
	}
	
	public <T> T getOrDefault(Argument.Operator<T> operator) {
		if (has(operator)) {
			Argument<T> argument = getArgument(operator);
			T value = argument.getValue();
			if (value != null) {
				return value;
			}
		}
		
		return operator.getDefaultValue();
	}
	
	public <T> boolean has(Argument.Operator<T> operator) {
		@SuppressWarnings("unchecked")
		Argument<T> argument = (Argument<T>)args.get(operator);
		
		if (argument == null) return false;
		if (argument.getValue() == null) return false;
		if (operator.getDefaultValue() == null) return false;
		
		return true;
	}
}
