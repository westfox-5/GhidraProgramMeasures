package it.westfox5.ghidra.util;

public class StringUtils {

	public static boolean notEmpty(String s) {
		return s != null && !s.isEmpty();
	}
	public static boolean isEmpty(String s) {
		return !notEmpty(s);
	}
	
	public static String repeat(String s, int n) {
		return new String(new char[n]).replace("\0", s);
	}
}