package it.westfox5.ghidra.measure;

import java.math.BigDecimal;

public class NumericMeasure extends Measure<BigDecimal> {

	public NumericMeasure(MeasureKey key, BigDecimal value) {
		super(key, value);
	}
}
