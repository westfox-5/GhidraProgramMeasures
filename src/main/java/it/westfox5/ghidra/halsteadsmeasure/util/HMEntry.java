package it.westfox5.ghidra.halsteadsmeasure.util;

import ghidra.program.model.listing.Instruction;

public class HMEntry {
	public static enum HMType {
		OPERATOR, OPERAND;
	}
	
	private final HMType type;
	private final String descriptor;
	private final Instruction instruction;
	
	public HMEntry(HMType type, String descriptor, Instruction instruction) {
		this.type = type;
		this.descriptor = descriptor;
		this.instruction = instruction;
	}

	public HMType getType() {
		return type;
	}
	
	public String getDescriptor() {
		return descriptor;
	}

	public Instruction getInstruction() {
		return instruction;
	}
	
	
	
}
