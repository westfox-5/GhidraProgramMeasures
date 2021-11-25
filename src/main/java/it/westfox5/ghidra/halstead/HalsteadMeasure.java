package it.westfox5.ghidra.halstead;

import it.westfox5.ghidra.measure.MeasureKey;

public enum HalsteadMeasure {
	NUM_DISTINCT_OPS("n1", "Number of distinct operators.", null),
	NUM_DISTINCT_OPNDS("n2", "Number of distinct operands.", null),
	NUM_OPS("N1", "Number of operators.", null),
	NUM_OPNDS("N2", "Number of operands.", null),
	VOCABULARY("n", "Program vocabulary.","n = n1 + n2"),
	LEN("N", "Program length.", "N = N1 + N2"),
	EST_LEN("N^", "Program estimated length.", "N^ = n1*log2(n1) + n2*log2(n2)"),
	VOLUME("V", "Program volume.", "V = N*log2(n)"),
	DIFFICULTY("D", "Program difficulty.", "D(n1/2) * (N2/n2)"),
	EFFORT("E", "Program effort of programming.", "E = D * V"),
	CODING_TIME("T", "Time taken to code the program.", "T = E / 18"),
	EST_ERRORS("B", "Number of estimated errors.", "B = V / 3000"),
	;
	
	private MeasureKey key;
	private HalsteadMeasure(String name, String description, String formula) {
		this.key = MeasureKey.make(name).description(description).formula(formula).build();
	}
	
	public MeasureKey key() {
		return this.key;
	}
}
