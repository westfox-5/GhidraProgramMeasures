package it.westfox5.ghidra.util.logger;

public interface Logger {
	static Logger msgLogger = new MsgLogger();
	
	
	static Boolean DEBUG = Boolean.FALSE;
	default void debug(Object originator, Object msg) {
		if (DEBUG) info(originator, msg);
	}
	void info(Object originator, Object msg);
	void err(Object originator, Object msg);
}
