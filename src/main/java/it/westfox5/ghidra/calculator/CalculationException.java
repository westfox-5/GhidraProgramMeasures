package it.westfox5.ghidra.calculator;

public class CalculationException extends Exception {
	public CalculationException() {
		super();
	}

	public CalculationException(String message, Throwable cause) {
		super(message, cause);
	}

	public CalculationException(String message) {
		super(message);
	}

	public CalculationException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public CalculationException(Throwable cause) {
		super(cause);
	}

}
