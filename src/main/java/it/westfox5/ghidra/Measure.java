package it.westfox5.ghidra;

import java.util.Objects;

public abstract class Measure<V> {
	
	public static class MeasureKey {
		private final String name, description;

		public MeasureKey(String name, String description) {
			super();
			this.name = name;
			this.description = description;
		}

		public String getName() {
			return name;
		}

		public String getDescription() {
			return description;
		}

		@Override
		public int hashCode() {
			return Objects.hash(name);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			MeasureKey other = (MeasureKey) obj;
			return Objects.equals(name, other.name);
		}

		
	}
	
	private MeasureKey key;
	private V value;
	
	public Measure(MeasureKey key, V value) {
		this.key = key;
		this.value = value;
	}
	
	public Measure(String name, V value, String descr) {
		this(new MeasureKey(name, descr), value);
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

	public String getDescription() {
		return key.getDescription();
	}

	public MeasureKey getKey() {
		return key;
	}

	public void setKey(MeasureKey key) {
		this.key = key;
	}
	
	
	
}
