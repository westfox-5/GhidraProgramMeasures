# Halstead-Measure-Ghidra
Ghidra plugin for calculating the Halstead's Measure of a program.

The plugin is capable of supporting new types of analysis and export formats. It can be installed in Ghidra graphical interface or used in headless mode via the command line.

## Installation

* Open Ghidra. On the project selection window, click on `File` and `Install Extension`.

* Click on the green **+** button on the top-right of the window and select the ZIP file located in the `<project-root-dir>\dist` folder. 

* Flag the checkbox for the `Halstead-Measure-Ghidra` plugin and confirm with `ok`.

* Restart Ghidra.

* If a window appears informing you about a new plugin found and asking about wheter to configure it or not, select yes, flag the `Halstead-Measure-Ghidra` plugin and confirm with `ok`.
Otherwise if no window appears, go to `File` > `Configure` and click on the `configure` link inside the `Experimental` section. You will find the `Halstead-Measure-Ghidra` plugin which can you select and confirm with `ok`.

* Open the `Window` toolbar and you will find the **Program Measure Calculator**.

## GUI Usage

Once activated, the plugin will perform the analysis and compute some measures on a given function of the program.

The list of measures calculated can be found in the Wikipedia page: [Halstead complexity measures](https://en.wikipedia.org/wiki/Halstead_complexity_measures).

By default the analyzed function is the `main` function.
You can choose another function to analyze by simply locate the desired function on the program listing and click in one of the instructions of the function.

The plugin will automatically detect the new location and calculate the start address of the function. When the **reload** button in the top-right of the plugin window is clicked, all the measures will be recalculated.

---

There is the possibility to export the analysis in the JSON format. 

Other formats will be available when the need arises.

## Headless Usage

Within the plugin, a Ghidra script has been implemented.

The script is located in the `<project-root-dir>\ghidra_scripts` folder and can be run using the following command:

```
<ghidra-root-dir>\support\analyzeHeadless \
	<path-to-ghidra-project> <ghidra-project-name> \
	-import <path-to-binary-file> \
	-postScript <project-root-dir>\ghidra_scripts\ProgramMeasuresScript.java \
		analysis=halstead analyze-function=main  export=json export-path=<path-to-export-filename>
```

The script must be called as a `-postScript`, since it needs the program to be analyzed.

The operations of the script can be customized via command line arguments. Command line arguments must have the format `arg_name=arg_value`.
The following table lists the currently supported arguments:

|     Arg. Name    | Arg. Value Constraints |                        Description                        |                     Default Value                     |   |
|:----------------:|:----------------------:|:---------------------------------------------------------:|:-----------------------------------------------------:|:-:|
|     analysis     |   [halstead, ]  | Type of analysis to be performed.                         |                        halstead                       |   |
| analyze-function |                        | Name of the function to analyze.                          |                          main                         |   |
|      export      |     [json, ]    | Type of export. If no present, no files will be generated |                          json                         |   |
|    export-path   |                        | Path to the desired export location (filename included)   | the default export path is <project-root-dir>\exports	|   |

## Eclipse integration for Development

Make sure that the GhidraDev extension for Eclipse is correctly installed.

* Import the project: 
    * Click on `File` and `Open Project from File System`
    * Select the root directory of the project and click `Finish`

* Configure Ghidra run: 
    * Click on the `GhidraDev` tab and select `link Ghidra...`
    * Select the Ghidra installation root directory and then select the current java project. Don't mark python interpreter option.
	* On the Run configuration, select `Run as` and then Ghidra.
