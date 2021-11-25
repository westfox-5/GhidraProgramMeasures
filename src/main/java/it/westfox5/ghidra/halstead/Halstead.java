package it.westfox5.ghidra.halstead;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import it.westfox5.ghidra.MeasuredProgram;
import it.westfox5.ghidra.halstead.Halstead.Entry.EntryType;
import it.westfox5.ghidra.measure.Measure;
import it.westfox5.ghidra.measure.NumericMeasure;
import it.westfox5.ghidra.util.NumberUtils;

/**		
 * Wrapper class for the Halstead's measures.
 */
public class Halstead extends MeasuredProgram {
	
	/** Keep the pointer to the instruction for each operator */
	private List<Entry> operators;
	/** Keep the pointer to the instruction for each operand */
	private List<Entry> operands;
		
	/** BigDecimal representation */
	private BigDecimal n1, N1; // num. operators [distinct, total]
	private BigDecimal n2, N2; // num. operands  [distinct, total]	
	
	private boolean loaded;
		
	public static Halstead.Builder make(Program program) {
		return new Halstead.Builder(program);
	}

	private Halstead(Program program) {
		super(program);
	}
	
	private void load(Map<String, List<Entry>> opOccurrences, Map<String, List<Entry>> opndOccurrences) {
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
			
			initMeasures();
			

			loaded = true;
		}
	}

	private void initMeasures() {
		addMeasure(new NumericMeasure(HalsteadMeasure.NUM_DISTINCT_OPS.key(), getNumDistinctOperators()));
		addMeasure(new NumericMeasure(HalsteadMeasure.NUM_DISTINCT_OPNDS.key(), getNumDistinctOperands()));
		addMeasure(new NumericMeasure(HalsteadMeasure.NUM_OPS.key(), getNumOperators()));
		addMeasure(new NumericMeasure(HalsteadMeasure.NUM_OPNDS.key(), getNumOperands()));
		addMeasure(new NumericMeasure(HalsteadMeasure.VOCABULARY.key(), getVocabulary()));
		addMeasure(new NumericMeasure(HalsteadMeasure.LEN.key(), getLength()));
		addMeasure(new NumericMeasure(HalsteadMeasure.EST_LEN.key(), getEstimatedLength()));
		addMeasure(new NumericMeasure(HalsteadMeasure.VOLUME.key(), getVolume()));
		addMeasure(new NumericMeasure(HalsteadMeasure.DIFFICULTY.key(), getDifficulty()));
		addMeasure(new NumericMeasure(HalsteadMeasure.EFFORT.key(), getEffort()));
		addMeasure(new NumericMeasure(HalsteadMeasure.CODING_TIME.key(), getCodingTime()));
		addMeasure(new NumericMeasure(HalsteadMeasure.EST_ERRORS.key(), getEstimatedErrors()));
	}
	
	@Override
	public String getMeasureName() {
		return "Halstead";
	}
	

	@Override
	public List<Measure<?>> getOrderedMeasures() {
		List<Measure<?>> list = new ArrayList<>();
		for (HalsteadMeasure hmKey: HalsteadMeasure.values()) {
			list.add(getMeasures().get(hmKey.key()));
		}
		return list;
	}

	public String getProgramName() {
		return getProgram().getName();
	}

	public List<Entry> getOperands() {
		return operands;
	}

	public void setOperands(List<Entry> operands) {
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
	private BigDecimal getVocabulary() {
		return n1.add(n2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Program Length: <strong>N</strong>
	 * 
	 * @return N1 + N2
	 */
	private BigDecimal getLength() {
		return N1.add(N2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Calculated Estimated Program Length: <strong>N^</strong>
	 * 
	 * @return n1*log2(n1) + n2*log2(n2)
	 */
	private BigDecimal getEstimatedLength() {
		BigDecimal n1_log2 = n1.multiply(NumberUtils.log2(n1));
		BigDecimal n2_log2 = n2.multiply(NumberUtils.log2(n2));
		return n1_log2.add(n2_log2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Program Volume: <strong>V</strong>
	 * 
	 * @return N * log2(n)
	 */
	private BigDecimal getVolume() {
		BigDecimal N = getLength();
		BigDecimal n = getVocabulary();
		return N.multiply(NumberUtils.log2(n), NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Difficulty of the program to write/understand: <string>D</strong>
	 * 
	 * @return (n1/2) * (N2/n2)
	 */
	private BigDecimal getDifficulty() {
		BigDecimal a = n1.divide(new BigDecimal(2), NumberUtils.DEFAULT_CONTEXT);
		BigDecimal b = N2.divide(n2, NumberUtils.DEFAULT_CONTEXT);
		return a.multiply(b, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Effort in coding the program: <strong>E</strong>
	 * 
	 * @return D * V
	 */
	private BigDecimal getEffort() {
		BigDecimal D = getDifficulty();
		BigDecimal V = getVolume();
		return D.multiply(V, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Time to code the program: <strong>T</strong>
	 * 
	 * @return E / 18
	 */
	private BigDecimal getCodingTime() {
		BigDecimal E = getEffort();
		return E.divide(new BigDecimal(18), NumberUtils.DEFAULT_CONTEXT);
	}

	/**
	 * Estimated number of Errors in the implementation: <strong>B</strong>
	 * 
	 * @return V / 3000
	 */
	private BigDecimal getEstimatedErrors() {
		BigDecimal V = getVolume();
		return V.divide(new BigDecimal(3000), NumberUtils.DEFAULT_CONTEXT);
	}

	public static class Builder {
		private Program program;
		
		/** Keep the pointer to the instruction for each operator */
		private final Map<String, List<Entry>> opOccurrences = new HashMap<>();
		/** Keep the pointer to the instruction for each operand */
		private final Map<String, List<Entry>> opndOccurrences = new HashMap<>();
		
		public Builder(Program program) {
			this.program = program;
		}
		
		public Builder addOperator(String opDescriptor, Instruction instruction) {
			_addToMap(opOccurrences, opDescriptor, new Entry(EntryType.OPERATOR, opDescriptor, instruction));
			return this;
		}
		
		public Builder addOperand(String opndDescriptor, Instruction instruction) {
			_addToMap(opndOccurrences, opndDescriptor, new Entry(EntryType.OPERAND, opndDescriptor, instruction));
			return this;
		}
	
		public Halstead build() {
			Halstead hm = new Halstead(program);
			hm.load(opOccurrences, opndOccurrences);
			
			return hm;
		}
		

		private <V extends Entry> void _addToMap(Map<String, List<V>> map, String key, V value) {
			List<V> list = map.get(key);
			if (list == null) {
				list = new ArrayList<>();
				map.put(key, list);
			}
	
			list.add(value);
		}
	}
	
	public static class Entry {
		public static enum EntryType {
			OPERATOR, OPERAND;
		}
		
		private final EntryType type;
		private final String descriptor;
		private final Instruction instruction;
		
		public Entry(EntryType type, String descriptor, Instruction instruction) {
			this.type = type;
			this.descriptor = descriptor;
			this.instruction = instruction;
		}
	
		public EntryType getType() {
			return type;
		}
		
		public String getDescriptor() {
			return descriptor;
		}
	
		public Instruction getInstruction() {
			return instruction;
		}
		
		
		
	}


}