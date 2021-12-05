package it.westfox5.ghidra.util.logger;

import static it.westfox5.ghidra.plugin.ProgramMeasuresPlugin.DEBUG;

public interface Logger {
	static Logger msgLogger = new MsgLogger();
	
	default void debug(Object originator, Object msg) {
		if (DEBUG) info(originator, msg);
	}
	void info(Object originator, Object msg);
	void err(Object originator, Object msg);
}
