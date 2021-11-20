package halsteadsmeasure;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Instruction;

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
	
	private Integer numDistinctOperators, numTotalOperators;
	private Integer numDistinctOperands, numTotalOperands;
	
	public static HalsteadsMeasure.Builder make() {
		return new HalsteadsMeasure.Builder();
	}

	private HalsteadsMeasure(Map<String, List<Instruction>> opOccurrences, Map<String, List<Instruction>> opndOccurrences) {
		this.opOccurrences = opOccurrences;
		this.opndOccurrences = opndOccurrences; 
		
		init();
	}
	
	private void init() {
		this.numDistinctOperators = opOccurrences.keySet().size();
		this.numDistinctOperands = opndOccurrences.keySet().size();
		
		this.numTotalOperators = opOccurrences.values()	// Collection<List<V>>
					.stream()
					.flatMap(List::stream)				// from List<List<V>> to List<V>
					.collect(Collectors.toList())
					.size();
		this.numTotalOperands = opndOccurrences.values()	// Collection<List<V>>
					.stream()
					.flatMap(List::stream)				// from List<List<V>> to List<V>
					.collect(Collectors.toList())
					.size();
	}
	
	
	public Map<String, List<Instruction>> getOpOccurrences() {
		return opOccurrences;
	}

	public Map<String, List<Instruction>> getOpndOccurrences() {
		return opndOccurrences;
	}

	public Integer getNumDistinctOperators() {
		return numDistinctOperators;
	}

	public Integer getNumTotalOperators() {
		return numTotalOperators;
	}

	public Integer getNumDistinctOperands() {
		return numDistinctOperands;
	}

	public Integer getNumTotalOperands() {
		return numTotalOperands;
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