package it.westfox5.ghidra.measure;

public abstract class Measure<V> {
	
	private MeasureKey key;
	private V value;
	
	public Measure(MeasureKey key, V value) {
		this.key = key;
		this.value = value;
	}

	public String getName() {
		return key.getName();
	}

	public V getValue() {
		return value;
	}

	public void setValue(V value) {
		this.value = value;
	}
	
	public MeasureKey getKey() {
		return key;
	}

	public void setKey(MeasureKey key) {
		this.key = key;
	}
	
}
