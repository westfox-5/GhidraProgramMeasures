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
/**
 * @author liger
 *
 */
public class HalsteadsMeasure {
	
	/** Keep the pointer to the instruction for each operator */
	private final Map<String, List<Instruction>> opOccurrences;
	/** Keep the pointer to the instruction for each operand */
	private final Map<String, List<Instruction>> opndOccurrences;

	protected HalsteadsMeasure() {
		this.opOccurrences = new HashMap<>();
		this.opndOccurrences = new HashMap<>();
	}
	
	/** EXTERNAL INTERFACE */
	
	public void addOperator(String op, Instruction instruction) {
		_safe_addToMap(opOccurrences, op, instruction);
	}
	
	public void addOperand(String opnd, Instruction instruction) {
		_safe_addToMap(opndOccurrences, opnd, instruction);
	}
	
	public int countDistinctOperators() {
		return _safe_map(opOccurrences).keySet().size();
	}
	
	public int countDistinctOperands() {
		return _safe_map(opndOccurrences).keySet().size();
	}
	
	public int countOperators() {
		return _safe_map(opOccurrences).values()	// Collection<List<V>>
				.stream()
				.flatMap(List::stream)				// from List<List<V>> to List<V>
				.collect(Collectors.toList())
				.size();
	}
	
	public int countOperands() {
		return _safe_map(opndOccurrences).values()	// Collection<List<V>>
				.stream()
				.flatMap(List::stream)				// from List<List<V>> to List<V>
				.collect(Collectors.toList())
				.size();
	}
	
	
	
	
	public Map<String, List<Instruction>> getOpOccurrences() {
		return _safe_map(opOccurrences);
	}

	public Map<String, List<Instruction>> getOpndOccurrences() {
		return _safe_map(opndOccurrences);
	}

	/** INTERNAL UTILITIES */
	
	private <K, V> Map<K, V> _safe_map(Map<K,V> map) {
		if (map == null) return new HashMap<>();
		return map;
	}
	
	private <V extends Instruction> void _safe_addToMap(Map<String, List<V>> map, String key, V value) {
		map = _safe_map(map);
		
		List<V> list = map.get(key);
		if (list == null) {
			list = new ArrayList<>();
			map.put(key, list);
		}

		list.add(value);
	}
}