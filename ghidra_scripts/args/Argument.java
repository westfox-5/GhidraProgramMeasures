package args;

import java.util.HashMap;
import java.util.Map;

public class Argument<V> {
	private ArgOperation argOp;
	private V value;
	
	private Argument<?> containerArgRef;
	
	public Argument(ArgOperation argOp, V value) {
		this.argOp = argOp;
		this.value = value;
	}
	
	private Argument(ArgOperation argOp, V value, Argument<?> containerArgRef) {
		this(argOp, value);
		this.containerArgRef = containerArgRef;
	}

	
	public ArgOperation getArgOperation() {
		return argOp;
	}
	public void setArgOp(ArgOperation argOp) {
		this.argOp = argOp;
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

		private Map<ArgOperation, Argument<?>> subArgs; // must be of same type as principal
		
		public MultiArgument(ArgOperation argOp, V value) {
			super(argOp, value);
		}
		
		public <T> void addArg(ArgOperation argOp, T value) {
			if (subArgs == null) {
				subArgs = new HashMap<>();
			}
			Argument<T> subArg = new Argument<>(argOp, value, this);
			subArgs.put(argOp, subArg);
		}

		public Map<ArgOperation, Argument<?>> getSubArgs() {
			return subArgs;
		}

		
		
	}
}
