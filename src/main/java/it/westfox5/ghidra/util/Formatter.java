package it.westfox5.ghidra.util;

public class Formatter {
	
	public static enum Symbol {
		TAB("\t"), TWO_SPACES("  "), FOUR_SPACES("    ");
		
		private String str;
		private Symbol(String str) {
			this.str = str;
		}
		public String get() { 
			return str; 
		}
	}

	private StringBuilder sb;
	private Integer indentationLevel;
	private Symbol sym = Symbol.TWO_SPACES;
	
	public Formatter() {
		this.indentationLevel = 0;
		this.sb = new StringBuilder();
	}
	
	public Formatter(Symbol useSymbol) {
		this();
		this.sym=useSymbol;
	}
	
	public Formatter indent() {
		this.indentationLevel++;
		return this;
	}
	
	public Formatter write(String line) {
		sb.append(StringUtils.repeat(sym.get(), indentationLevel));
		sb.append(line);
		if (!line.endsWith("\n")) {
			sb.append("\n");
		}
		return this;
	}
	
	public Formatter outdent() {
		this.indentationLevel--;
		return this;
	}
	
	public String get() {
		return sb.toString();
	}
	
	public StringBuilder getSb() { 
		return sb;
	}
	
	public boolean validateIndentation() {
		return this.indentationLevel == 0;
	}
	
	public Integer getIndentationLevel() {
		return indentationLevel;
	}

	@Override
	public String toString() {
		return get();
	}
	
	
}
