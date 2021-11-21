package it.westfox5.ghidra.halsteadsmeasure.util;

public class StringUtils {

	public static boolean notEmpty(String s) {
		return s != null && !s.isEmpty();
	}
	public static boolean isEmpty(String s) {
		return !notEmpty(s);
	}
}