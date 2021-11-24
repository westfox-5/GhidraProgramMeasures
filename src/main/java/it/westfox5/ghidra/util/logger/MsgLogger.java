package it.westfox5.ghidra.util.logger;

import ghidra.util.Msg;

public class MsgLogger implements Logger {

	@Override
	public void info(Object originator, Object msg) {
		Msg.info(originator, msg);
	}

	@Override
	public void err(Object originator, Object msg) {
		Msg.error(originator, msg);
	}

}
