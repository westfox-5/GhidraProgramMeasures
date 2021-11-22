package it.westfox5.ghidra.halsteadsmeasure;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Instruction;
import it.westfox5.ghidra.halsteadsmeasure.util.HMEntry;
import it.westfox5.ghidra.halsteadsmeasure.util.HMEntry.HMType;
import it.westfox5.ghidra.halsteadsmeasure.util.NumberUtils;

/**		
 * number of unique (distinct) operators (n1)
 * number of unique (distinct) operands (n2)
 * total number of operators (N1)
 * total number of operands (N2).
 * 
 * Wrapper class for the Halstead's measures.
 */
public class HalsteadsMeasure {
	
	private final String programName;
	
	/** Keep the pointer to the instruction for each operator */
	private List<HMEntry> operators;
	/** Keep the pointer to the instruction for each operand */
	private List<HMEntry> operands;
		
	/** BigDecimal representation */
	private BigDecimal n1, N1; // num. operators [distinct, total]
	private BigDecimal n2, N2; // num. operands  [distinct, total]	
	
	private boolean loaded;
	
	public static HalsteadsMeasure.Builder make(String programName) {
		return new HalsteadsMeasure.Builder(programName);
	}

	private HalsteadsMeasure(String programName) {
		this.programName = programName;
	}
	
	private void load(Map<String, List<HMEntry>> opOccurrences, Map<String, List<HMEntry>> opndOccurrences) {
		// @see Pitfall #1 in: <a href="https://blogs.oracle.com/javamagazine/post/four-common-pitfalls-of-the-bigdecimal-class-and-how-to-avoid-them">https:blogs.oracle.com</a>
		if (!loaded) {
			// distinct operators/operands number is the number of keys we have in the map
			Integer _distinct_ops = opOccurrences.keySet().size();
			this.n1 = BigDecimal.valueOf(_distinct_ops);
			Integer _distinct_opnds = opndOccurrences.keySet().size();
			this.n2 = BigDecimal.valueOf(_distinct_opnds);
			
			// total operators/operands number is the union of the occurrences we have in the map
			this.operators = opOccurrences.values()
						.stream()
						.flatMap(List::stream)	// from List<List<V>> to List<V>
						.collect(Collectors.toList());
			this.N1 = BigDecimal.valueOf(operators.size());
	
			this.operands = opndOccurrences.values()
						.stream()
						.flatMap(List::stream)	// from List<List<V>> to List<V>
						.collect(Collectors.toList());
			this.N2 = BigDecimal.valueOf(operands.size());
			
			loaded = true;
		}
	}
	
	public String getProgramName() {
		return programName;
	}


	public List<HMEntry> getOperands() {
		return operands;
	}

	public void setOperands(List<HMEntry> operands) {
		this.operands = operands;
	}

	public BigDecimal getNumDistinctOperators() {
		return n1;
	}

	public BigDecimal getNumOperators() {
		return N1;
	}

	public BigDecimal getNumDistinctOperands() {
		return n2;
	}

	public BigDecimal getNumOperands() {
		return N2;
	}

	/** 
	 * Program Vocabulary: <strong>n</strong>
	 * 
	 * @return n1 + n2
	 */
	public BigDecimal getVocabulary() {
		return n1.add(n2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Program Length: <strong>N</strong>
	 * 
	 * @return N1 + N2
	 */
	public BigDecimal getLength() {
		return N1.add(N2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Calculated Estimated Program Length: <strong>N^</strong>
	 * 
	 * @return n1*log2(n1) + n2*log2(n2)
	 */
	public BigDecimal getEstimatedLength() {
		BigDecimal n1_log2 = n1.multiply(NumberUtils.log2(n1));
		BigDecimal n2_log2 = n2.multiply(NumberUtils.log2(n2));
		return n1_log2.add(n2_log2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Program Volume: <strong>V</strong>
	 * 
	 * @return N * log2(n)
	 */
	public BigDecimal getVolume() {
		BigDecimal N = getLength();
		BigDecimal n = getVocabulary();
		return N.multiply(NumberUtils.log2(n), NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Difficulty of the program to write/understand: <string>D</strong>
	 * 
	 * @return (n1/2) * (N2/n2)
	 */
	public BigDecimal getDifficulty() {
		BigDecimal a = n1.divide(new BigDecimal(2), NumberUtils.DEFAULT_CONTEXT);
		BigDecimal b = N2.divide(n2, NumberUtils.DEFAULT_CONTEXT);
		return a.multiply(b, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Effort in coding the program: <strong>E</strong>
	 * 
	 * @return D * V
	 */
	public BigDecimal getEffort() {
		BigDecimal D = getDifficulty();
		BigDecimal V = getVolume();
		return D.multiply(V, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Time to code the program: <strong>T</strong>
	 * 
	 * @return E / 18
	 */
	public BigDecimal getCodingTime() {
		BigDecimal E = getEffort();
		return E.divide(new BigDecimal(18), NumberUtils.DEFAULT_CONTEXT);
	}

	/**
	 * Estimated number of Errors in the implementation: <strong>B</strong>
	 * 
	 * @return V / 3000
	 */
	public BigDecimal getEstimatedErrors() {
		BigDecimal V = getVolume();
		return V.divide(new BigDecimal(3000), NumberUtils.DEFAULT_CONTEXT);
	}

	public static class Builder {
		
		private String programName;
		
		/** Keep the pointer to the instruction for each operator */
		private final Map<String, List<HMEntry>> opOccurrences = new HashMap<>();
		/** Keep the pointer to the instruction for each operand */
		private final Map<String, List<HMEntry>> opndOccurrences = new HashMap<>();
		
		public Builder(String programName) {
			this.programName = programName;
		}
		
		public Builder addOperator(String opDescriptor, Instruction instruction) {
			_addToMap(opOccurrences, opDescriptor, new HMEntry(HMType.OPERATOR, opDescriptor, instruction));
			return this;
		}
		
		public Builder addOperand(String opndDescriptor, Instruction instruction) {
			_addToMap(opndOccurrences, opndDescriptor, new HMEntry(HMType.OPERAND, opndDescriptor, instruction));
			return this;
		}
	
		public HalsteadsMeasure build() {
			HalsteadsMeasure hm = new HalsteadsMeasure(programName);
			hm.load(opOccurrences, opndOccurrences);
			
			return hm;
		}
		

		private <V extends HMEntry> void _addToMap(Map<String, List<V>> map, String key, V value) {
			List<V> list = map.get(key);
			if (list == null) {
				list = new ArrayList<>();
				map.put(key, list);
			}
	
			list.add(value);
		}
	}
}