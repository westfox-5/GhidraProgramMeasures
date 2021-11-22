package it.westfox5.ghidra.halsteadsmeasure.export;


/** Mapping of supported export types */ 
public enum FileExtension {
	JSON(".json");
	
	private final String ext;
	private FileExtension(String ext) {
		this.ext = ext;
	}
	
	public String ext() { return this.ext; }
	
}