package it.westfox5.ghidra.halsteadsmeasure;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Instruction;
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
	
	/** Keep the pointer to the instruction for each operator */
	private final Map<String, List<Instruction>> opOccurrences;
	/** Keep the pointer to the instruction for each operand */
	private final Map<String, List<Instruction>> opndOccurrences;
		
	/** BigDecimal representation */
	private BigDecimal n1, N1; // num. operators [distinct, total]
	private BigDecimal n2, N2; // num. operands  [distinct, total]	
	
	public static HalsteadsMeasure.Builder make() {
		return new HalsteadsMeasure.Builder();
	}

	private HalsteadsMeasure(Map<String, List<Instruction>> opOccurrences, Map<String, List<Instruction>> opndOccurrences) {
		this.opOccurrences = opOccurrences;
		this.opndOccurrences = opndOccurrences; 
		
		init();
	}
	
	/**
	 * @see Pitfall #1 in: <a href="https://blogs.oracle.com/javamagazine/post/four-common-pitfalls-of-the-bigdecimal-class-and-how-to-avoid-them">https:blogs.oracle.com</a> 
	 */
	private void init() {
		Integer _distinct_ops = opOccurrences.keySet().size();
		this.n1 = BigDecimal.valueOf(_distinct_ops);
		Integer _distinct_opnds = opndOccurrences.keySet().size();
		this.n2 = BigDecimal.valueOf(_distinct_opnds);
		
		Integer _ops = opOccurrences.values()	// Collection<List<V>>
					.stream()
					.flatMap(List::stream)				// from List<List<V>> to List<V>
					.collect(Collectors.toList())
					.size();
		this.N1 = BigDecimal.valueOf(_ops);

		Integer _opnds = opndOccurrences.values()	// Collection<List<V>>
					.stream()
					.flatMap(List::stream)				// from List<List<V>> to List<V>
					.collect(Collectors.toList())
					.size();
		this.N2 = BigDecimal.valueOf(_opnds);

	}
	
	public Map<String, List<Instruction>> getOpOccurrences() {
		return opOccurrences;
	}

	public Map<String, List<Instruction>> getOpndOccurrences() {
		return opndOccurrences;
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
	public BigDecimal getProgramVocabulary() {
		return n1.add(n2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Program Length: <strong>N</strong>
	 * 
	 * @return N1 + N2
	 */
	public BigDecimal getProgramLength() {
		return N1.add(N2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Calculated Estimated Program Length: <strong>N^</strong>
	 * 
	 * @return n1*log2(n1) + n2*log2(n2)
	 */
	public BigDecimal getProgramEstimatedLength() {
		BigDecimal n1_log2 = n1.multiply(NumberUtils.log2(n1));
		BigDecimal n2_log2 = n2.multiply(NumberUtils.log2(n2));
		return n1_log2.add(n2_log2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Program Volume: <strong>V</strong>
	 * 
	 * @return N * log2(n)
	 */
	public BigDecimal getProgramVolume() {
		BigDecimal N = getProgramLength();
		BigDecimal n = getProgramVocabulary();
		return N.multiply(NumberUtils.log2(n), NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Difficulty of the program to write/understand: <string>D</strong>
	 * 
	 * @return (n1/2) * (N2/n2)
	 */
	public BigDecimal getProgramDifficulty() {
		BigDecimal a = n1.divide(new BigDecimal(2), NumberUtils.DEFAULT_CONTEXT);
		BigDecimal b = N2.divide(n2, NumberUtils.DEFAULT_CONTEXT);
		return a.multiply(b, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Effort in coding the program: <strong>E</strong>
	 * 
	 * @return D * V
	 */
	public BigDecimal getProgramEffort() {
		BigDecimal D = getProgramDifficulty();
		BigDecimal V = getProgramVolume();
		return D.multiply(V, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Time to code the program: <strong>T</strong>
	 * 
	 * @return E / 18
	 */
	public BigDecimal getProgramCodingTime() {
		BigDecimal E = getProgramEffort();
		return E.divide(new BigDecimal(18), NumberUtils.DEFAULT_CONTEXT);
	}

	/**
	 * Estimated number of Errors in the implementation: <strong>B</strong>
	 * 
	 * @return V / 3000
	 */
	public BigDecimal getProgramEstimatedErrors() {
		BigDecimal V = getProgramVolume();
		return V.divide(new BigDecimal(3000), NumberUtils.DEFAULT_CONTEXT);
	}

	public static class Builder {
		/** Keep the pointer to the instruction for each operator */
		private final Map<String, List<Instruction>> opOccurrences = new HashMap<>();
		/** Keep the pointer to the instruction for each operand */
		private final Map<String, List<Instruction>> opndOccurrences = new HashMap<>();
		
		
		public Builder addOperator(String op, Instruction instruction) {
			_addToMap(opOccurrences, op, instruction);
			return this;
		}
		
		public Builder addOperand(String opnd, Instruction instruction) {
			_addToMap(opndOccurrences, opnd, instruction);
			return this;
		}
	
		public HalsteadsMeasure build() {
			HalsteadsMeasure hm = new HalsteadsMeasure(opOccurrences, opndOccurrences);
			
			return hm;
		}
		

		private <V extends Instruction> void _addToMap(Map<String, List<V>> map, String key, V value) {
			List<V> list = map.get(key);
			if (list == null) {
				list = new ArrayList<>();
				map.put(key, list);
			}
	
			list.add(value);
		}
	}
}