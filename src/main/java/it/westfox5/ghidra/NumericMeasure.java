package it.westfox5.ghidra;

import java.math.BigDecimal;

public class NumericMeasure extends Measure<BigDecimal> {

	public NumericMeasure(String name, BigDecimal value, String descr) {
		super(name, value, descr);
	}

	public NumericMeasure(MeasureKey key, BigDecimal value) {
		super(key, value);
	}
	
	

}
