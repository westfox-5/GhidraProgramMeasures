package it.westfox5.ghidra.measure;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import it.westfox5.ghidra.util.StringUtils;

public class MeasureKey {
	public static final String KEY_DESCRIPTION = "description";
	public static final String KEY_FORMULA = "formula";
	
	private final String name;
	private final Map<String, String> otherValues;

	private MeasureKey(String name) {
		super();
		this.name = name;
		
		this.otherValues = new HashMap<>();
	}

	public String getName() {
		return name;
	}
	
	public String getAdditionalValue(String key) {
		return otherValues.get(key);
	}

	public Set<String> getAdditionalKeys() {
		return otherValues.keySet();
	}
	
	public static MeasureKey.Builder make(String name) {
		return new MeasureKey.Builder(name);
	}
	
	public static class Builder {
		private final String name;
		private final Map<String, String> otherValues;
		private Builder(String name) {
			this.name = name;
			this.otherValues = new HashMap<>();
		}
		
		public Builder description(String description) {
			if (StringUtils.notEmpty(description)) { 
				otherValues.put(KEY_DESCRIPTION, description);
			}
			return this;
		}
		public Builder formula(String formula) {
			if (StringUtils.notEmpty(formula)) { 
				otherValues.put(KEY_FORMULA, formula);
			}
			return this;
		}
		
		public Builder additional(String key, String value) {
			if (StringUtils.notEmpty(key) && StringUtils.notEmpty(value)) { 
				otherValues.put(key, value);
			}
			return this;
		}
		
		public MeasureKey build() {
			MeasureKey key = new MeasureKey(name);
			key.otherValues.putAll(this.otherValues);
			
			return key;
		}
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