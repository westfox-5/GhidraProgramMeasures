package it.westfox5.ghidra.halsteadsmeasure.export;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;

import it.westfox5.ghidra.halsteadsmeasure.HMException;
import it.westfox5.ghidra.halsteadsmeasure.HalsteadsMeasure;
import it.westfox5.ghidra.halsteadsmeasure.util.StringUtils;

// TODO: make generic with a `Program` interface!
public abstract class HMExporter {
	
	public static Path EXPORT_LOCATION;
	static {
		String workingDir = System.getProperty("user.dir");
		EXPORT_LOCATION = Path.of(workingDir, "exports");
	}

	private String filename;
	private FileExtension extension;
	
	protected HMExporter(String filename, FileExtension fileExtension) {
		this.filename = filename;
		this.extension = fileExtension;
		
		initExportDirectory();
	}
	
	/**
	 * Each HMExporter implementation must provide his custom format.
	 * 
	 * @param hm the HalsteadsMeasure obj to dump to file
	 * @return stringBuilder containing the file content
	 */
	public abstract StringBuilder getFileContent(HalsteadsMeasure hm);
	
	
	private void initExportDirectory() {
		if (!Files.exists(EXPORT_LOCATION)) {
			try {
				Files.createDirectory(EXPORT_LOCATION);
			} catch(IOException e ) {
				throw new RuntimeException(e);
			}
		}
	}
	
	private void validateFilename() throws HMException {
		if (StringUtils.isEmpty(filename)) 
			throw new HMException("No file name is provided to the exporter.");
		
		if (extension == null)
			throw new HMException("No file extension is provided to the exporter.");
		
		if (StringUtils.isEmpty(extension.ext()))
			throw new HMException("Cannot determine file extension for the provided extension `"+extension.name()+"`.");
	}
	
	private String getFilename() {
		return filename + extension.ext();
	}
		
	public File export(HalsteadsMeasure hm) throws HMException, IOException {
		validateFilename();
		
		StringBuilder sb = getFileContent(hm);
		if (sb.length() < 1) {
			throw new HMException("No content was generated by the `"+ getClass().getCanonicalName() + "` implementation of `getFileContent` method");
		}
		
		Path destPath = EXPORT_LOCATION.resolve(getFilename());

		// default options are CREATE, TRUNCATE_EXISTING, and WRITE
		// @see https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/nio/file/Files.html#writeString(java.nio.file.Path,java.lang.CharSequence,java.nio.charset.Charset,java.nio.file.OpenOption...)
		Files.writeString(destPath, sb, Charset.forName("UTF-8")); 
		
		return destPath.toFile();
	}
}