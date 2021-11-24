import ghidra.app.script.GhidraScript;

public class HMPreScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		System.out.println("Pre-Script!");
	}

}
